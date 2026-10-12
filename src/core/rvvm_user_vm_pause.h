/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_VM_PAUSE_H
#define RVVM_USER_VM_PAUSE_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "user_fd_guard.h"

/* A mapping transition must also stop kernel writes into guest buffers.
 * Delivering a signal waits for a blocking syscall to leave the kernel before
 * acknowledging the pause. The owner uses only allocation-free operations
 * while peers are parked: a peer can be holding a native allocator lock. */
#define USER_VM_MAX_THREADS 4096
static struct {
    uint32_t active, generation;
    size_t count;
    struct { pid_t tid; uint32_t ready; } threads[USER_VM_MAX_THREADS];
} user_vm_pause;
static __thread bool user_vm_private_wake;
/* A resource service has its own signal/rlimit group, but coordinates the
 * original guest group's mappings. Ordinary guest processes use getpid(). */
static __thread pid_t user_vm_service_group;

static pid_t user_vm_pause_group(void)
{
    return user_vm_service_group ? user_vm_service_group : getpid();
}
/* The reaper blocks guest signals. Its lock excludes kernel writes to guest
 * TIDs during a transition, without delaying joins for an entire vfork. */
static uint32_t user_vm_reaper_tid, user_vm_initial_tid;
static user_fd_mutex_t user_vm_reaper_lock;
static uint32_t user_vm_pi_users, user_vm_shared_active;
static __thread unsigned user_vm_pi_owned;
static int user_vm_pause_collect(pid_t self);

static int user_vm_pause_add(pid_t tid, pid_t self)
{
    if (!tid || tid == self) return 0;
    if (user_vm_pause.count == USER_VM_MAX_THREADS) { errno = EAGAIN; return -1; }
    size_t i = user_vm_pause.count++;
    user_vm_pause.threads[i].tid = tid;
    user_vm_pause.threads[i].ready = 3; /* Not signaled yet. */
    return 0;
}

static bool user_vm_task_gone(pid_t pid, pid_t tid)
{
    if (syscall(SYS_tgkill, pid, tid, 0) && errno == ESRCH) return true;
    /* The original process thread may remain a zombie until its group exits.
     * A zombie has finished kernel robust-list and clear_child_tid writes. */
    char path[64], status[4096];
    snprintf(path, sizeof(path), "/proc/%u/stat", (unsigned)tid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t count = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (count <= 0) return false;
    status[count] = 0;
    char* name = strrchr(status, ')');
    return name && name[1] == ' ' && (name[2] == 'Z' || name[2] == 'X');
}

static void user_vm_pause_checkpoint(void)
{
    while (__atomic_load_n(&user_vm_pause.active, __ATOMIC_ACQUIRE))
        syscall(SYS_futex, &user_vm_pause.active, 128, 1, NULL, NULL, 0);
}

static bool user_vm_pause_signal(siginfo_t* info)
{
    if (info->si_code != SI_QUEUE || info->si_pid != getpid()
        || info->si_value.sival_ptr != &user_vm_pause) return false;
    int saved = errno;
    if ((uint32_t)info->si_errno == user_vm_pause.generation) {
        pid_t tid = syscall(SYS_gettid);
        for (size_t i = 0; i < user_vm_pause.count; ++i) {
            if (user_vm_pause.threads[i].tid != tid) continue;
            if (__atomic_load_n(&user_vm_pause.active, __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&user_vm_pause.threads[i].ready, 1, __ATOMIC_RELEASE);
                syscall(SYS_futex, &user_vm_pause.threads[i].ready, 129, 1, NULL, NULL, 0);
                user_vm_private_wake = true;
                user_vm_pause_checkpoint();
            }
            /* Drain this generation before the owner can start another.
             * Otherwise a peer can remain in the old handler and miss its
             * next pause acknowledgment; standard signals can coalesce. */
            __atomic_store_n(&user_vm_pause.threads[i].ready, 2, __ATOMIC_RELEASE);
            syscall(SYS_futex, &user_vm_pause.threads[i].ready, 129, 1, NULL, NULL, 0);
            break;
        }
    }
    errno = saved;
    return true;
}

static void user_vm_pause_end(void)
{
    __atomic_store_n(&user_vm_pause.active, 0, __ATOMIC_RELEASE);
    syscall(SYS_futex, &user_vm_pause.active, 129, INT_MAX, NULL, NULL, 0);
    for (size_t i = 0; i < user_vm_pause.count; ++i) {
        uint32_t state;
        while ((state = __atomic_load_n(&user_vm_pause.threads[i].ready, __ATOMIC_ACQUIRE)) < 2) {
            struct timespec timeout = {.tv_sec = 0, .tv_nsec = 10000000};
            syscall(SYS_futex, &user_vm_pause.threads[i].ready, 128, state, &timeout, NULL, 0);
            if (user_vm_task_gone(user_vm_pause_group(), user_vm_pause.threads[i].tid)) break;
        }
    }
    user_fd_mutex_unlock(&user_vm_reaper_lock);
}

static int user_vm_pause_begin(void)
{
    user_fd_mutex_lock(&user_vm_reaper_lock);
    pid_t self = syscall(SYS_gettid), pid = user_vm_pause_group();
    user_vm_pause.count = 0;
    if (user_vm_pause_collect(self)) goto fail;
    ++user_vm_pause.generation;
    __atomic_store_n(&user_vm_pause.active, 1, __ATOMIC_RELEASE);
    for (size_t i = 0; i < user_vm_pause.count; ++i) {
        if (user_vm_task_gone(pid, user_vm_pause.threads[i].tid)) {
            user_vm_pause.threads[i].ready = 2;
            continue;
        }
        siginfo_t info = {0};
        info.si_signo = SIGSEGV;
        info.si_code = SI_QUEUE;
        info.si_pid = pid;
        info.si_uid = getuid();
        info.si_errno = user_vm_pause.generation;
        info.si_value.sival_ptr = &user_vm_pause;
        __atomic_store_n(&user_vm_pause.threads[i].ready, 0, __ATOMIC_RELEASE);
        if (syscall(SYS_rt_tgsigqueueinfo, pid, user_vm_pause.threads[i].tid, SIGSEGV, &info)) {
            __atomic_store_n(&user_vm_pause.threads[i].ready, 3, __ATOMIC_RELEASE);
            if (errno != ESRCH) goto fail;
        }
    }
    for (size_t i = 0; i < user_vm_pause.count; ++i) {
        while (!__atomic_load_n(&user_vm_pause.threads[i].ready, __ATOMIC_ACQUIRE)) {
            struct timespec timeout = {.tv_sec = 0, .tv_nsec = 10000000};
            syscall(SYS_futex, &user_vm_pause.threads[i].ready, 128, 0, &timeout, NULL, 0);
            if (user_vm_task_gone(pid, user_vm_pause.threads[i].tid)) break;
        }
    }
    return 0;
fail: {
        int error = errno;
        user_vm_pause_end();
        errno = error;
        return -1;
    }
}

#endif
