/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#include "user_fd_guard.h"
#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "locking.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include "utils.h"

static user_fd_mutex_t shared_guard;
static THREAD_LOCAL user_fd_guard_t* selected_guard;
#define guard (*(selected_guard ? &selected_guard->lock : &shared_guard))
static THREAD_LOCAL unsigned depth;
static THREAD_LOCAL uint32_t owner_tid;
static THREAD_LOCAL void (*resume_table)(void);

void user_fd_mutex_lock(user_fd_mutex_t* lock)
{
    int saved = errno;
    if (!owner_tid) owner_tid = syscall(SYS_gettid);
    for (;;) {
        uint32_t owner = 0;
        if (atomic_cas_uint32_ex(&lock->owner, &owner, owner_tid, false, ATOMIC_ACQUIRE, ATOMIC_RELAXED)) break;
        if (!(owner & 0x80000000U)) {
            uint32_t waiting = owner | 0x80000000U;
            if (!atomic_cas_uint32_ex(&lock->owner, &owner, waiting, false, ATOMIC_RELAXED, ATOMIC_RELAXED)) continue;
            owner = waiting;
        }
        syscall(SYS_futex, &lock->owner, FUTEX_WAIT_PRIVATE, owner, NULL, NULL, 0);
    }
    errno = saved;
}

void user_fd_mutex_unlock(user_fd_mutex_t* lock)
{
    int saved = errno;
    uint32_t owner = atomic_swap_uint32_ex(&lock->owner, 0, ATOMIC_RELEASE);
    if (owner & 0x80000000U)
        syscall(SYS_futex, &lock->owner, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
    errno = saved;
}

void user_fd_mutex_recover(user_fd_mutex_t* lock, uint32_t tid)
{
    int saved = errno;
    uint32_t owner = atomic_load_uint32_relax(&lock->owner);
    while (tid && (owner & 0x7FFFFFFFU) == tid) {
        if (atomic_cas_uint32_ex(&lock->owner, &owner, 0, false, ATOMIC_RELEASE, ATOMIC_RELAXED)) {
            if (owner & 0x80000000U)
                syscall(SYS_futex, &lock->owner, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
            break;
        }
    }
    errno = saved;
}

user_fd_guard_t* user_fd_guard_create(void)
{
    user_fd_guard_t* state = safe_new_obj(user_fd_guard_t);
    state->refs = 1;
    return state;
}

user_fd_guard_t* user_fd_guard_retain(user_fd_guard_t* state)
{
    if (state) atomic_add_uint32(&state->refs, 1);
    return state;
}

void user_fd_guard_release(user_fd_guard_t* state)
{
    if (state && atomic_sub_uint32(&state->refs, 1) == 1) free(state);
}

void user_fd_guard_select(user_fd_guard_t* state)
{
    assert(state == selected_guard || !depth);
    selected_guard = state;
    resume_table = NULL;
}

void user_fd_guard_set_resume(void (*resume)(void)) { resume_table = resume; }

void user_fd_lock(void)
{
    int saved = errno;
    bool outer = !depth;
    if (outer) user_fd_mutex_lock(&guard);
    depth++;
    if (outer && resume_table) resume_table();
    errno = saved;
}

void user_fd_unlock(void)
{
    int saved = errno;
    assert(depth);
    if (!--depth) user_fd_mutex_unlock(&guard);
    errno = saved;
}

void user_fd_fork_reset(void)
{
    assert(depth);
    /* Fork removes every other waiter; retain this thread's ownership. */
    owner_tid = syscall(SYS_gettid);
    atomic_store_uint32_relax(&guard.owner, owner_tid);
}

void user_fd_guard_child(void) { owner_tid = syscall(SYS_gettid); }

void user_fd_guard_recover(uint32_t tid)
{
    user_fd_mutex_recover(&guard, tid);
    depth = 0;
    owner_tid = syscall(SYS_gettid);
}
#endif
