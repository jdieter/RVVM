/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PTRACE_SYSCALL_H
#define RVVM_USER_PTRACE_SYSCALL_H
#include "core/rvvm.h"

/* Published in the ptrace bridge, so use fixed-width fields across processes. */
struct user_ptrace_syscall_state {
    uint32_t phase, reserved;
    uint64_t nr, args[6], ip, sp;
    int64_t result;
};

void user_ptrace_syscall_entry(rvvm_hart_t*, struct user_ptrace_syscall_state*);
void user_ptrace_syscall_refresh_entry(rvvm_hart_t*, struct user_ptrace_syscall_state*);
void user_ptrace_syscall_exit(rvvm_hart_t*, struct user_ptrace_syscall_state*);
size_t user_ptrace_syscall_info(const struct user_ptrace_syscall_state*, bool, void*, size_t);
#endif
