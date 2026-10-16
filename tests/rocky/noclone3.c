/* SPDX-License-Identifier: GPL-3.0-or-later */
/* noclone3 [--eperm] program [args...]: run a host program with clone3
 * refused, as under Docker's and Podman's default seccomp profiles (ENOSYS)
 * or sandboxes that answer EPERM. The filter is inherited across exec and
 * fork, so wrap rvvm_user itself, or a guest started through binfmt_misc:
 *
 *     cc -O2 -o noclone3 tests/rocky/noclone3.c
 *     ./noclone3 rvvm_user guest [args...]
 *     ./noclone3 --eperm rvvm_user guest [args...]
 *
 * Every other syscall, and clone3 on another architecture's syscall table,
 * is allowed. Exits with 2 when the filter cannot be installed. glibc falls
 * back to clone only on ENOSYS: with --eperm its pthread_create fails. */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#elif defined(__riscv) && __riscv_xlen == 64
#define NATIVE_ARCH AUDIT_ARCH_RISCV64
#else
#error "Unknown host architecture"
#endif

int main(int argc, char** argv)
{
    int error = ENOSYS;
    if (argc > 1 && !strcmp(argv[1], "--eperm")) {
        error = EPERM;
        ++argv;
        --argc;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: noclone3 [--eperm] program [args...]\n");
        return 2;
    }
    /* clone3 is 435 in the generic and x86_64 tables alike. */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_ARCH, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 435, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof(filter) / sizeof(*filter), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) {
        perror("noclone3: seccomp");
        return 2;
    }
    execvp(argv[1], argv + 1);
    perror("noclone3: exec");
    return 2;
}
