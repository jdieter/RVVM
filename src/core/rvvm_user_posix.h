/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_POSIX_H
#define RVVM_USER_POSIX_H

_Static_assert(sizeof(long) == 8 && sizeof(struct iovec) == 16
               && offsetof(struct iovec, iov_len) == 8, "RV64 iovec ABI");
_Static_assert(sizeof(struct sched_param) == 4
               && offsetof(struct sched_param, sched_priority) == 0, "RV64 scheduler ABI");
_Static_assert(sizeof(struct timespec) == 16
               && offsetof(struct timespec, tv_nsec) == 8, "RV64 timespec ABI");

static long user_posix_vector(long nr, uintptr_t fd, uintptr_t iov, uintptr_t count,
                              uintptr_t low, uintptr_t high, uintptr_t flags)
{
    /* Linux's native LP64 ABI carries the entire offset in low; high is not
     * a 32-bit upper half. v2 flags are the sixth argument, even on RV64. */
    return errno_ret(USER_SYSCALL(nr, fd, iov, count, low, high, flags));
}

static long user_posix_scheduler(unsigned nr, uintptr_t a0, uintptr_t a1, uintptr_t a2)
{
    /* The host kernel validates guest pointers, PIDs, policies and permissions.
     * In particular, a bad getparam pointer must not crash the emulator. */
    switch (nr) {
        case 118: return errno_ret(syscall(SYS_sched_setparam, (int)a0, a1));
        case 119: return errno_ret(syscall(SYS_sched_setscheduler, (int)a0, (int)a1, a2));
        case 120: return errno_ret(syscall(SYS_sched_getscheduler, (int)a0));
        case 121: return errno_ret(syscall(SYS_sched_getparam, (int)a0, a1));
        case 125: return errno_ret(syscall(SYS_sched_get_priority_max, (int)a0));
        case 126: return errno_ret(syscall(SYS_sched_get_priority_min, (int)a0));
        case 127: return errno_ret(syscall(SYS_sched_rr_get_interval, (int)a0, a1));
        default: return -ENOSYS;
    }
}
#endif
