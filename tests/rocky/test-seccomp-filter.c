/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "atomics.h"
#include "utils.h"

static long user_memory_copy(void* to, const void* from, size_t size)
{
    memcpy(to, from, size);
    return 0;
}
static bool user_native_child_active;
#include "core/rvvm_user_seccomp.h"

int main(void)
{
    struct sock_filter policy[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 278, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {4, policy};
    assert(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    assert(!user_seccomp_call(SECCOMP_SET_MODE_FILTER, 0, &prog));
    struct seccomp_data data = {.nr = 278, .arch = AUDIT_ARCH_RISCV64};
    assert(user_seccomp_check(&data) == -ENOSYS);
    data.nr = 172;
    assert(user_seccomp_check(&data) == 1);
    policy[1].k = 172;
    policy[2].k = SECCOMP_RET_ERRNO | 65535;
    assert(!user_seccomp_install(0, &prog));
    assert(user_seccomp_check(&data) == -4095);
    data.nr = 278;
    assert(user_seccomp_check(&data) == -ENOSYS);
    struct user_seccomp_filter* inherited = user_seccomp_retain(user_seccomp);
    user_seccomp_release(user_seccomp);
    user_seccomp = inherited;
    assert(user_seccomp_check(&data) == -ENOSYS);
    uint32_t action = SECCOMP_RET_ERRNO;
    assert(!user_seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, &action));
    action = SECCOMP_RET_TRACE;
    assert(user_seccomp_call(SECCOMP_GET_ACTION_AVAIL, 0, &action) == -EOPNOTSUPP);
    assert(user_seccomp_install(SECCOMP_FILTER_FLAG_TSYNC, &prog) == -EINVAL);
    /* Bad control flow, unaligned loads, uninitialized scratch memory,
     * invalid ALU operations and unsupported actions must fail at install. */
    policy[0].k = 1;
    assert(!user_seccomp_valid(policy, 4));
    policy[0].k = 0;
    policy[1].jt = 2;
    assert(!user_seccomp_valid(policy, 4));
    policy[1].jt = 0;
    policy[0].code = BPF_LD | BPF_W | BPF_MEM;
    assert(!user_seccomp_valid(policy, 4));
    policy[0].code = BPF_ALU | BPF_DIV | BPF_K;
    assert(!user_seccomp_valid(policy, 4));
    policy[0].code = BPF_LD | BPF_W | BPF_ABS;
    policy[2].k = SECCOMP_RET_KILL_PROCESS;
    assert(!user_seccomp_valid(policy, 4));
    struct sock_filter shift[] = {
        BPF_STMT(BPF_LD | BPF_IMM, 1),
        BPF_STMT(BPF_LDX | BPF_IMM, 32),
        BPF_STMT(BPF_ALU | BPF_LSH | BPF_X, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    prog = (struct sock_fprog){6, shift};
    assert(!user_seccomp_install(0, &prog));
    assert(user_seccomp_check(&data) == -EACCES);
    user_seccomp_release(user_seccomp);
    return 0;
}
