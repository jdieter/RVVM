/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PTRACE_REPLAY_H
#define RVVM_USER_PTRACE_REPLAY_H
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
struct user_ptrace_replay_entry {
    uint64_t token;
    siginfo_t info;
    pid_t sender;
};
int user_ptrace_replay_queue(pid_t, pid_t, const siginfo_t*);
int user_ptrace_replay_store_unsent(pid_t, const siginfo_t*);
size_t user_ptrace_replay_count(pid_t);
int user_ptrace_replay_export(pid_t, struct user_ptrace_replay_entry*, size_t);
bool user_ptrace_replay_pending(pid_t);
bool user_ptrace_replay_hold(pid_t, const siginfo_t*);
int user_ptrace_replay_resend(pid_t, pid_t);
bool user_ptrace_replay_take(pid_t, const siginfo_t*, siginfo_t*);
/* Allocate only at the runtime transfer stop with signal handlers blocked. */
struct user_ptrace_replay_entry* user_ptrace_replay_allocate(size_t);
bool user_ptrace_replay_restore(siginfo_t*);
void user_ptrace_replay_thread_destroy(void);
void user_ptrace_replay_remove(pid_t);
void user_ptrace_replay_fork_reset(void);
#endif
