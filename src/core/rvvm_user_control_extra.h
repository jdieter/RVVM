/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_CONTROL_EXTRA_H
#define RVVM_USER_CONTROL_EXTRA_H

_Static_assert(sizeof(long) == 8 && sizeof(void*) == 8, "RV64 control syscall LP64 ABI");

static long user_control_extra(unsigned nr, uintptr_t a0, uintptr_t a1,
                               uintptr_t a2, uintptr_t a3)
{
    switch (nr) {
        case 30: return errno_ret(syscall(SYS_ioprio_set, (int)a0, (int)a1, (int)a2));
        case 31: return errno_ret(syscall(SYS_ioprio_get, (int)a0, (int)a1));
        case 81: return errno_ret(USER_SYSCALL(SYS_sync, 0, 0, 0, 0, 0, 0));
        case 84: return errno_ret(USER_SYSCALL(SYS_sync_file_range, (int)a0,
                                             (int64_t)a1, (int64_t)a2, (unsigned)a3, 0, 0));
        case 213: return errno_ret(USER_SYSCALL(SYS_readahead, (int)a0,
                                              (int64_t)a1, (size_t)a2, 0, 0, 0));
        /* sched_attr uses fixed-width fields with the same layout on RV64 and
         * our LP64 hosts. Let Linux validate size/version, tail bytes, flags,
         * permissions and pointers, including its E2BIG size writeback. */
        case 274: return errno_ret(syscall(SYS_sched_setattr, (int)a0, a1, (unsigned)a2));
        case 275: return errno_ret(syscall(SYS_sched_getattr, (int)a0, a1, (unsigned)a2, (unsigned)a3));
        default: return -ENOSYS;
    }
}
#endif
