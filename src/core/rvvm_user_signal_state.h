/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_SIGNAL_STATE_H
#define RVVM_USER_SIGNAL_STATE_H
#include "util/atomics.h"
#include "util/spinlock.h"
#include "util/utils.h"
#include <stdlib.h>
#include <string.h>

struct user_sigaction { uint64_t handler, flags, mask; };
struct user_signal_process {
    spinlock_t lock;
    struct user_sigaction actions[65];
    bool private_installed[2];
    uint32_t refs;
};
static struct user_signal_process user_signal_initial = {.refs = 1};
static THREAD_LOCAL struct user_signal_process* user_signal_process;

static struct user_signal_process* user_signal_process_current(void)
{
    return user_signal_process ? user_signal_process : &user_signal_initial;
}

// Pthreads share dispositions; fork gives the process a private copy.
#define user_actions (user_signal_process_current()->actions)
#define user_private_installed (user_signal_process_current()->private_installed)
#define user_action_lock (user_signal_process_current()->lock)

static struct user_signal_process* user_signal_process_retain(void)
{
    struct user_signal_process* state = user_signal_process_current();
    atomic_add_uint32(&state->refs, 1);
    return state;
}

static void user_signal_process_release(struct user_signal_process* state)
{
    if (state && atomic_sub_uint32(&state->refs, 1) == 1 && state != &user_signal_initial) free(state);
}
#endif
