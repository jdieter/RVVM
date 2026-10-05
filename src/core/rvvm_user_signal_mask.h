/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_SIGNAL_MASK_H
#define RVVM_USER_SIGNAL_MASK_H
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static void user_signal_block_all(void)
{
    // pthread startup unblocks NPTL signals 32/33 despite the inherited mask.
    // TLS must stay private until guest signal state or the loan is ready.
    uint64_t all = UINT64_MAX;
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &all, NULL, sizeof(all)))
        rvvm_fatal("Cannot block signals during thread startup");
}
#endif
