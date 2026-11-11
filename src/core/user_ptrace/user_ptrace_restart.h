/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Included after rvvm_user_signal.h: restart decisions need guest sigactions. */
#ifndef RVVM_USER_PTRACE_RESTART_H
#define RVVM_USER_PTRACE_RESTART_H

static THREAD_LOCAL struct {
    uint64_t args[6];
    unsigned nr;
    clockid_t clock;
    struct timespec deadline;
    bool prepared, valid;
} user_ptrace_restart;

static void user_ptrace_restart_prepare(rvvm_hart_t* cpu)
{
    unsigned nr = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 17);
    if (nr != 98 && nr != 101 && nr != 115) return;
    if (user_ptrace_detour_active()) return;
    uint64_t args[6];
    for (unsigned i = 0; i < 6; i++) args[i] = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10 + i);
    bool absolute = false;
    clockid_t clock = CLOCK_MONOTONIC;
    uintptr_t timeout = args[0];
    if (nr == 98) {
        unsigned op = args[1] & FUTEX_CMD_MASK;
        if ((op != FUTEX_WAIT && op != FUTEX_WAIT_BITSET) || !args[3]) return;
        absolute = op == FUTEX_WAIT_BITSET;
        clock = (args[1] & FUTEX_CLOCK_REALTIME) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        timeout = args[3];
    } else if (nr == 115) {
        if (args[1] & TIMER_ABSTIME) return;
        /* Relative realtime sleeps must survive wall-clock adjustments. */
        clock = args[0] == CLOCK_REALTIME ? CLOCK_MONOTONIC : args[0];
        timeout = args[2];
    }
    user_ptrace_restart.prepared = user_ptrace_restart.valid = false;
    struct timespec value, now;
    if (uapi_extra_copy(&value, (void*)timeout, sizeof(value), false)
        || value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1000000000) return;
    if (!absolute) {
        if (clock_gettime(clock, &now)) return;
        if (value.tv_sec > INT64_MAX - now.tv_sec - 1) value = (struct timespec){INT64_MAX, 999999999};
        else {
            value.tv_sec += now.tv_sec;
            value.tv_nsec += now.tv_nsec;
            if (value.tv_nsec >= 1000000000) { value.tv_sec++; value.tv_nsec -= 1000000000; }
        }
    }
    memcpy(user_ptrace_restart.args, args, sizeof(args));
    user_ptrace_restart.nr = nr;
    user_ptrace_restart.clock = clock;
    user_ptrace_restart.deadline = value;
    user_ptrace_restart.prepared = true;
}

static struct timespec user_ptrace_restart_remaining(void)
{
    struct timespec now, remaining = {0};
    if (!clock_gettime(user_ptrace_restart.clock, &now)) {
        remaining.tv_sec = user_ptrace_restart.deadline.tv_sec - now.tv_sec;
        remaining.tv_nsec = user_ptrace_restart.deadline.tv_nsec - now.tv_nsec;
        if (remaining.tv_nsec < 0) { remaining.tv_nsec += 1000000000; remaining.tv_sec--; }
        if (remaining.tv_sec < 0) remaining = (struct timespec){0};
    }
    return remaining;
}

static void user_ptrace_restart_resume(void)
{
    if (user_ptrace_restart_requested()) user_ptrace_restart.valid = user_ptrace_restart.prepared;
}

static rvvm_addr_t user_ptrace_restart_syscall(void)
{
    if (!user_ptrace_restart.valid) return (rvvm_addr_t)-EINTR;
    const uint64_t* a = user_ptrace_restart.args;
    struct timespec timeout = user_ptrace_restart.deadline;
    if (user_ptrace_restart.nr == 98) {
        if ((a[1] & FUTEX_CMD_MASK) == FUTEX_WAIT) timeout = user_ptrace_restart_remaining();
        return errno_ret(USER_SYSCALL(SYS_futex, a[0], a[1], a[2], &timeout, a[4], a[5]));
    }
    rvvm_addr_t result = errno_ret(USER_SYSCALL(SYS_clock_nanosleep, user_ptrace_restart.clock,
                                               TIMER_ABSTIME, &timeout, NULL, 0, 0));
    uintptr_t remaining = user_ptrace_restart.nr == 101 ? a[1] : a[3];
    if ((int64_t)result == -EINTR && remaining) {
        timeout = user_ptrace_restart_remaining();
        if (uapi_extra_copy(&timeout, (void*)remaining, sizeof(timeout), true)) return (rvvm_addr_t)-EFAULT;
    }
    return result;
}

static int user_ptrace_restart_code(rvvm_hart_t* cpu, unsigned nr)
{
    unsigned long a1 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 11);
    unsigned long a3 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 13);
    if (nr == 128 && user_ptrace_restart.valid) return -516;
    if (nr == 101) return -516;
    if (nr == 115) return a1 & TIMER_ABSTIME ? -514 : -516;
    if (nr == 98 && a3 && ((a1 & FUTEX_CMD_MASK) == FUTEX_WAIT
                           || (a1 & FUTEX_CMD_MASK) == FUTEX_WAIT_BITSET)) return -516;
    if (nr == 72 || nr == 73 || nr == 133) return -514;
    return user_restart_syscall(cpu, nr) ? -512 : -EINTR;
}

static void user_ptrace_pending_signal(rvvm_hart_t* cpu)
{
    int pending = user_sig.pending;
    if (!pending) return;
    user_ptrace_deliver_signal(cpu, &pending, &user_sig.info);
    user_sig.pending = pending;
    if (!pending) {
        user_sig.synchronous = false;
        atomic_store_uint32(&cpu->user_signal_pending, 0);
        user_apply_mask();
    }
}

static bool user_ptrace_interrupt_syscall(rvvm_hart_t* cpu, unsigned nr, int64_t result)
{
    if (result != -EINTR || !user_sig.pending || !user_ptrace_tracing()) return false;
    rvvm_addr_t pc = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC);
    rvvm_addr_t arg0 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10);
    bool unstarted = user_sig.syscall_unstarted;
    int code = unstarted ? -512 : user_ptrace_restart_code(cpu, nr);
    if (code == -516 && user_ptrace_restart.prepared) user_ptrace_restart.valid = true;
    /* Linux exposes its restart code before signal delivery, not the eventual
     * EINTR or restored argument that the guest handler sees in its frame. */
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 10, code);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, pc + 4);
    user_ptrace_syscall_end(cpu);
    user_ptrace_pending_signal(cpu);
    if (code != -EINTR && (int64_t)rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10) == code
        && rvvm_read_cpu_reg(cpu, RVVM_REGID_PC) == pc + 4) {
        bool restart = unstarted || !user_sig.pending;
        if (user_sig.pending) {
            spin_lock(&user_action_lock);
            struct user_sigaction action = user_actions[user_sig.pending];
            spin_unlock(&user_action_lock);
            restart |= action.handler == 1 || code == -513 || (code == -512 && (action.flags & SA_RESTART));
        }
        if (code == -516 && restart && !user_ptrace_restart.valid) restart = false;
        rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 10, restart ? arg0 : (rvvm_addr_t)-EINTR);
        if (restart) {
            rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, pc);
            if (code == -516) rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 17, 128);
        } else if (code == -516) user_ptrace_restart.valid = false;
    }
    return true;
}
#endif
