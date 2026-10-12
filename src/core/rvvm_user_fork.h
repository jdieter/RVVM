/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FORK_H
#define RVVM_USER_FORK_H

#ifdef RVVM_STATIC_GLIBC_FORK
#include <linux/futex.h>
#include <linux/sched.h>
#include <sys/prctl.h>

static __thread unsigned user_fork_signal = SIGCHLD;
static __thread unsigned user_fork_flags;
static __thread bool user_fork_want_pidfd;
static __thread int* user_fork_pidfd;
static __thread int* user_fork_native_tid;
static __thread struct robust_list_head* user_fork_native_robust;
static __thread bool user_fork_native_saved;
pid_t __real__Fork(void);
extern void __getrandom_fork_subprocess(void) __attribute__((weak));

/* Guest set_tid_address/set_robust_list replace the kernel registrations.
 * Save the native TCB locations once, before any guest syscall can do so. */
static void user_host_fork_init(void)
{
    if (user_fork_native_saved) return;
    user_fork_native_saved = true;
    int saved = errno;
    size_t length;
    if (syscall(SYS_get_robust_list, 0, &user_fork_native_robust, &length)
        || !user_fork_native_robust || length != sizeof(*user_fork_native_robust)) {
        user_fork_native_tid = NULL;
        user_fork_native_robust = NULL;
    } else {
        /* In these NPTL ABIs tid precedes robust_prev. The kernel's
         * clear_child_tid registration need not name libc's cached TID. */
        user_fork_native_tid = (void*)((char*)user_fork_native_robust - 2 * sizeof(void*));
        if (*user_fork_native_tid != syscall(SYS_gettid)) {
            user_fork_native_tid = NULL;
            user_fork_native_robust = NULL;
        }
    }
    errno = saved;
}

/* GNU ld wraps libc's _Fork call, inside fork's malloc/stdio/loader locking
 * and child recovery. A bare clone here would otherwise inherit held locks.
 * Dynamic libc binds this call internally, so this backend is static-only. */
pid_t __wrap__Fork(void)
{
    unsigned signal = user_fork_signal;
    unsigned extra = user_fork_flags;
    user_fork_signal = SIGCHLD;
    user_fork_flags = 0;
    if (signal == SIGCHLD && !extra) return __real__Fork();
    int* tid = user_fork_native_tid;
    struct robust_list_head* robust = user_fork_native_robust;
    if (!tid || !robust) { errno = ENOTSUP; return -1; }
    struct clone_args args = {
        .flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | extra,
        .child_tid = (uintptr_t)tid,
        .pidfd = (uintptr_t)user_fork_pidfd,
        .exit_signal = signal,
    };
    pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0 && errno == ENOSYS) {
        unsigned flags = (unsigned)args.flags | signal;
#ifdef __aarch64__
        pid = syscall(SYS_clone, flags, NULL, user_fork_pidfd, NULL, tid);
#else
        pid = syscall(SYS_clone, flags, NULL, user_fork_pidfd, tid, NULL);
#endif
    }
    if (!pid) {
        /* These supported glibc NPTL ABIs place robust_prev immediately
         * before the kernel's head. Ownership never survives fork. */
        ((void**)robust)[-1] = &robust->list;
        robust->list.next = &robust->list;
        syscall(SYS_set_robust_list, robust, sizeof(*robust));
        if (__getrandom_fork_subprocess) __getrandom_fork_subprocess();
    }
    return pid;
}
#else
static void user_host_fork_init(void) {}
#endif

static pid_t user_host_fork(unsigned signal)
{
#ifdef RVVM_STATIC_GLIBC_FORK
    user_fork_signal = signal;
    pid_t pid = fork();
    user_fork_signal = SIGCHLD;
    return pid;
#else
    if (signal != SIGCHLD) { errno = ENOSYS; return -1; }
    return fork();
#endif
}

static pid_t user_host_fork_files(unsigned signal, bool shared)
{
#ifdef RVVM_STATIC_GLIBC_FORK
    user_fork_flags = (shared ? CLONE_FILES : 0) | (user_fork_want_pidfd ? CLONE_PIDFD : 0);
#else
    if (shared) { errno = ENOSYS; return -1; }
#endif
    return user_host_fork(signal);
}
#endif
