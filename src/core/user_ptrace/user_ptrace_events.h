/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PTRACE_EVENTS_H
#define RVVM_USER_PTRACE_EVENTS_H
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

struct user_ptrace_event {
    pid_t pid, pgid, owner_tid;
    dev_t pidfd_dev;
    ino_t pidfd_ino;
    int status;
    bool traced, info_valid, eventmsg_valid, deferred;
    siginfo_t info;
    unsigned long eventmsg;
    struct rusage usage;
};

struct user_ptrace_stop {
    pid_t pid, owner_tid;
    bool stopped;
    unsigned long options, resume_request;
    struct user_ptrace_event event;
    uint64_t bridge_hint, hart_hint;
};

/* All returned records are copies. No call invokes ptrace or resumes a child. */
bool user_ptrace_events_push(const struct user_ptrace_event*);
/* Capture the native tracer TID and stable pidfd identity before native reap. */
void user_ptrace_events_identify(struct user_ptrace_event*);
void user_ptrace_events_normalize_lock(void);
void user_ptrace_events_normalize_unlock(void);
bool user_ptrace_events_tracing(void);
uint32_t user_ptrace_events_generation(void);
uint32_t* user_ptrace_events_sleep_begin(void);
void user_ptrace_events_sleep_end(void);
bool user_ptrace_events_pending(void);
bool user_ptrace_events_release(pid_t);
bool user_ptrace_events_pop_deferred(pid_t, struct user_ptrace_event*);
bool user_ptrace_events_wait4(pid_t selector, pid_t caller_pgid, int options,
                             struct user_ptrace_event*);
bool user_ptrace_events_waitid(idtype_t, id_t, pid_t caller_pgid, int options,
                              struct user_ptrace_event*);
bool user_ptrace_events_get(pid_t, struct user_ptrace_stop*);
bool user_ptrace_events_set(const struct user_ptrace_stop*);
bool user_ptrace_events_inherit(pid_t parent, pid_t child);
void user_ptrace_events_remove(pid_t);
/* Child-only, immediately after fork: inherited tracer state is not its own. */
void user_ptrace_events_fork_reset(void);
#endif
