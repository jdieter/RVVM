/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_MSG_H
#define RVVM_USER_MSG_H
#include <stddef.h>
#include <sys/msg.h>
#include <asm/msgbuf.h>

/* RV64 and supported LP64 hosts share the raw Linux IPC ABI. Keep original
 * pointers so permission checks and partial copies retain kernel semantics. */
_Static_assert(sizeof(long) == 8 && sizeof(struct msqid64_ds) == 120, "RV64 msqid64_ds ABI");
_Static_assert(offsetof(struct msqid64_ds, msg_stime) == 48
               && offsetof(struct msqid64_ds, msg_rtime) == 56
               && offsetof(struct msqid64_ds, msg_ctime) == 64
               && offsetof(struct msqid64_ds, msg_cbytes) == 72
               && offsetof(struct msqid64_ds, msg_qnum) == 80
               && offsetof(struct msqid64_ds, msg_qbytes) == 88
               && offsetof(struct msqid64_ds, msg_lspid) == 96
               && offsetof(struct msqid64_ds, msg_lrpid) == 100
               && offsetof(struct msqid64_ds, __unused4) == 104
               && offsetof(struct msqid64_ds, __unused5) == 112, "RV64 message queue fields");
_Static_assert(sizeof(struct msginfo) == 32 && offsetof(struct msginfo, msgseg) == 28, "RV64 msginfo ABI");

static long user_msg_syscall(unsigned nr, uintptr_t a0, uintptr_t a1,
                           uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    switch (nr) {
        case 186:
            return uapi_extra_result(syscall(SYS_msgget, (key_t)a0, (int)a1));
        case 187:
            return uapi_extra_result(syscall(SYS_msgctl, (int)a0, (int)a1, a2));
        case 188:
            return uapi_extra_result(USER_SYSCALL(SYS_msgrcv, (int)a0, a1, a2, (long)a3, (int)a4, 0));
        case 189:
            return uapi_extra_result(USER_SYSCALL(SYS_msgsnd, (int)a0, a1, a2, (int)a3, 0, 0));
        default:
            return -ENOSYS;
    }
}
#endif
