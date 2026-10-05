/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include "core/rvvm_user_signal_state.h"
#include "core/rvvm_user_signal_mask.h"
#include "util/user_fd_guard.h"

static atomic_int waiting, acquired, proceed;
static user_fd_guard_t* child_guard;
static void* worker(void* opaque)
{
    user_signal_block_all();
    uint64_t mask;
    assert(!syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &mask, sizeof(mask)));
    assert(mask == (UINT64_MAX & ~(UINT64_C(1) << (SIGKILL - 1))
                               & ~(UINT64_C(1) << (SIGSTOP - 1))));
    user_signal_process = opaque;
    user_fd_guard_select(child_guard);
    atomic_store(&waiting, 1);
    user_fd_lock();
    atomic_store(&acquired, 1);
    while (!atomic_load(&proceed)) sched_yield();
    assert(user_actions[10].handler == 22);
    user_actions[10].handler = 33;
    user_fd_unlock();
    user_fd_guard_select(NULL);
    user_signal_process_release(user_signal_process);
    return NULL;
}
int main(void)
{
    user_signal_initial.actions[10].handler = 11;
    user_signal_process = safe_new_obj(struct user_signal_process);
    user_signal_process->refs = 1;
    user_actions[10].handler = 22;
    child_guard = user_fd_guard_create();
    user_fd_guard_select(child_guard);
    user_fd_lock();
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, worker, user_signal_process_retain()));
    while (!atomic_load(&waiting)) sched_yield();
    struct timespec delay = {.tv_nsec = 50000000};
    nanosleep(&delay, NULL);
    assert(!atomic_load(&acquired));
    user_fd_unlock();
    // The original child leader can exit while its pthread still owns state.
    user_signal_process_release(user_signal_process);
    user_signal_process = NULL;
    atomic_store(&proceed, 1);
    assert(!pthread_join(thread, NULL));
    assert(user_signal_initial.actions[10].handler == 11);
    user_fd_guard_select(NULL);
    user_fd_guard_release(child_guard);
    puts("PASS startup signal mask, process signal lifetime and shared descriptor guard");
}
