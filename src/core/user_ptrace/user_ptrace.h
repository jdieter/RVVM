/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PTRACE_H
#define RVVM_USER_PTRACE_H
#include "core/rvvm.h"
#include "user_ptrace_replay.h"
#include <signal.h>
#include <sys/types.h>
#define USER_PTRACE_WAIT_AGAIN (-4096L)

/* A kernel VFORK child borrows the suspended caller's TLS, but owns its
 * tracee bridge and signal replay buffers. Tracer event queues stay with
 * their native process; these handles don't transfer wait ownership. */
struct user_ptrace_context {
    void* bridge;
    uint32_t* executable_fd;
    bool stepped;
    void* events;
    struct user_ptrace_replay_context replay;
};
void user_ptrace_context_save(struct user_ptrace_context*);
void user_ptrace_context_load(const struct user_ptrace_context*);
void user_ptrace_process_init(rvvm_hart_t*, uint64_t*, volatile sig_atomic_t*, void*);

void user_ptrace_init(rvvm_hart_t*, const uint64_t*, size_t, uint64_t*, volatile sig_atomic_t*, void*);
void* user_ptrace_prepare(rvvm_hart_t*, const uint64_t*, size_t, uint64_t);
void user_ptrace_cancel(void*);
void user_ptrace_fork(rvvm_hart_t*);
void user_ptrace_destroy(void);
void user_ptrace_dispatch(void);
void user_ptrace_exit(rvvm_hart_t*);
void user_ptrace_clone(rvvm_hart_t*);
bool user_ptrace_syscall_begin(rvvm_hart_t*);
void user_ptrace_syscall_end(rvvm_hart_t*);
bool user_ptrace_tracing(void);
void user_ptrace_deliver_signal(rvvm_hart_t*, volatile sig_atomic_t*, siginfo_t*);
void user_ptrace_guest_fault(void);
void user_ptrace_checkpoint(rvvm_hart_t*);
bool user_ptrace_signal(rvvm_hart_t*, int, const siginfo_t*);
bool user_ptrace_injected(int, siginfo_t*);
bool user_ptrace_restore_signal(siginfo_t*);
bool user_ptrace_break(rvvm_hart_t*);
bool user_ptrace_interrupted(void);
rvvm_addr_t user_ptrace_run(rvvm_hart_t*);
long user_ptrace_request(unsigned long, pid_t, uintptr_t, uintptr_t);
long user_ptrace_wait(long, int*);
long user_ptrace_waitid(long, siginfo_t*, int);
bool user_ptrace_wait_ready(pid_t, int*, int, void*, long*);
bool user_ptrace_waitid_ready(int, unsigned, siginfo_t*, int, void*, long*);
bool user_ptrace_remote_auxv(pid_t, uint64_t[64], size_t*);
bool user_ptrace_remote_exe_descriptor(pid_t, char*, size_t);
bool user_ptrace_guest_task(pid_t, pid_t, bool*);
void user_ptrace_set_exe_fd_pointer(uint32_t*);
#endif
