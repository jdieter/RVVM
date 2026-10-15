/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FORK_H
#define RVVM_USER_FORK_H
#include <linux/futex.h>
#ifndef SYS_clone3
#define SYS_clone3 435
#endif

/* Host forks. An ordinary fork (exit signal SIGCHLD, no extra flags) uses
 * libc's fork(): libc then recovers all of its own state in the child,
 * RVVM's allocator joins in through pthread_atfork, and the fork holds the
 * thread lifecycle lock. Every other fork-like
 * child (user_host_fork() below) and every private-mm VFORK child
 * (rvvm_user_native_vfork.h) is a raw clone of one thread, recovered with
 * user_host_fork_child(): this works with any libc and any clone flags.
 *
 * The libc rule. A raw clone runs no libc recovery: every libc lock that
 * another thread holds at that moment stays held in the child. So after
 * startup, RVVM code on any thread calls only libc functions that take no
 * process-wide lock, or whose lock the raw fork itself holds:
 * - allocation is RVVM's own (rvvm_user_malloc.c), locked across the clone;
 * - thread creation, joins and detaches go through rvvm_thread_*, which the
 *   fork excludes (libc's thread list and stack cache), and no thread is
 *   detached, since a detached thread's exit is not excluded;
 * - no stdio streams: logging writes directly, proc files are read with
 *   user_proc_read.h;
 * - no NSS (getpwnam_r and friends), dlopen, system/popen, setenv, exit or
 *   atexit, setuid-family wrappers (they signal every thread), and no libc
 *   getrandom/arc4random (raw syscalls instead).
 * Startup, before a second thread exists, is exempt; so is a fatal abort.
 * Plain syscall wrappers, string and formatting functions are fine.
 *
 * libc keeps believing the vanished threads exist (its thread list, its
 * thread count): they are never joined or signalled in the child, and their
 * stacks and allocator caches stay allocated. */

static __thread int* user_fork_native_tid;
static __thread struct robust_list_head* user_fork_native_robust;
static __thread bool user_fork_native_saved;

/* The kernel ABI's struct clone_args, without a libc-dependent header. */
struct user_clone_args {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

/* Guest set_tid_address/set_robust_list replace the kernel registrations.
 * Find this thread's libc TID and robust-list head once, before any guest
 * syscall can do so. The robust head is the kernel's registration. In the
 * NPTL layout the cached TID sits two words below it; accept that only when
 * it holds this thread's TID. Otherwise raw forks are refused, not guessed. */
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
        user_fork_native_tid = (void*)((char*)user_fork_native_robust - 2 * sizeof(void*));
        if (*user_fork_native_tid != syscall(SYS_gettid)) {
            user_fork_native_tid = NULL;
            user_fork_native_robust = NULL;
        }
    }
    errno = saved;
}

/* A raw fork of this thread can recover libc's thread identity. */
static bool user_host_fork_ready(void)
{
    return user_fork_native_tid && user_fork_native_robust;
}

/* Child side of a raw fork, before anything else runs: Linux leaves no robust
 * list registered and the parent's TID in libc's cache, and the locks taken by
 * user_host_fork_lock() belong to the parent. Ownership never survives fork,
 * so the list starts empty, as libc's fork leaves it. RVVM's threads hold no
 * libc robust mutex; the descriptor guard's own markers on this list are
 * dropped with it, which user_fd_fork_select() expects. Raw syscalls only. */
static void user_host_fork_child(void)
{
    struct robust_list_head* robust = user_fork_native_robust;
    *user_fork_native_tid = syscall(SYS_gettid);
    robust->list.next = &robust->list;
    robust->list_op_pending = NULL;
    syscall(SYS_set_robust_list, robust, sizeof(*robust));
    rvvm_thread_fork_child();
    user_malloc_fork_child();
}

/* Callers hold RVVM's own locks first: these come last. */
static void user_host_fork_lock(void)
{
    rvvm_thread_fork_lock();
    user_malloc_fork_lock();
}

static void user_host_fork_unlock(void)
{
    user_malloc_fork_unlock();
    rvvm_thread_fork_unlock();
}

/* A fork-like child of this thread with any exit signal and extra clone
 * flags (CLONE_FILES, namespaces). Returns twice, as fork(). */
static pid_t user_host_fork(unsigned signal, uint64_t extra)
{
    if (signal == SIGCHLD && !extra) {
        /* libc resets its own state, not the lifecycle lock: a reader
         * inside pthread_create would leave the child unable to fork. */
        rvvm_thread_fork_lock();
        pid_t pid = fork();
        int saved = errno;
        if (pid) rvvm_thread_fork_unlock();
        else rvvm_thread_fork_child();
        errno = saved;
        return pid;
    }
    if (!user_host_fork_ready()) { errno = ENOTSUP; return -1; }
    int* tid = user_fork_native_tid;
    struct user_clone_args args = {
        .flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | extra,
        .child_tid = (uintptr_t)tid,
        .exit_signal = signal,
    };
    user_host_fork_lock();
    pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0 && errno == ENOSYS) {
        /* Seccomp policies may still refuse clone3. */
        unsigned long flags = args.flags | signal;
#ifdef __aarch64__
        pid = syscall(SYS_clone, flags, NULL, NULL, NULL, tid);
#else
        pid = syscall(SYS_clone, flags, NULL, NULL, tid, NULL);
#endif
    }
    if (!pid) {
        user_host_fork_child();
        return 0;
    }
    int saved = errno;
    user_host_fork_unlock();
    errno = saved;
    return pid;
}
#endif
