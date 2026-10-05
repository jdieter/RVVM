/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_IPC_H
#define RVVM_USER_IPC_H
#include <mqueue.h>
#include <stddef.h>
#include <sys/sem.h>

/* These RV64 layouts match the supported LP64 Linux hosts. Passing the
 * original pointers preserves kernel validation order and partial effects. */
_Static_assert(sizeof(struct mq_attr) == 64 && offsetof(struct mq_attr, mq_curmsgs) == 24, "RV64 mq_attr ABI");
_Static_assert(sizeof(struct sembuf) == 6 && offsetof(struct sembuf, sem_op) == 2
               && offsetof(struct sembuf, sem_flg) == 4, "RV64 sembuf ABI");
_Static_assert(sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8, "RV64 timespec ABI");
_Static_assert(O_NONBLOCK == 00004000, "RV64 mq_flags ABI");

static long user_ipc_syscall(unsigned nr, uintptr_t a0, uintptr_t a1,
                           uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    switch (nr) {
        case 181: /* mq_unlink: raw Linux names omit libc's leading slash. */
            return uapi_extra_result(syscall(SYS_mq_unlink, a0));
        case 182:
            return uapi_extra_result(USER_SYSCALL(SYS_mq_timedsend, (int)a0, a1, a2, (unsigned)a3, a4, 0));
        case 183:
            return uapi_extra_result(USER_SYSCALL(SYS_mq_timedreceive, (int)a0, a1, a2, a3, a4, 0));
        case 185:
            return uapi_extra_result(syscall(SYS_mq_getsetattr, (int)a0, a1, a2));
        case 190:
            return uapi_extra_result(syscall(SYS_semget, (key_t)a0, (int)a1, (int)a2));
        case 192:
            return uapi_extra_result(USER_SYSCALL(SYS_semtimedop, (int)a0, a1, a2, a3, 0, 0));
        case 193:
            return uapi_extra_result(USER_SYSCALL(SYS_semop, (int)a0, a1, a2, 0, 0, 0));
        default:
            return -ENOSYS;
    }
}
#endif
