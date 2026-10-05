/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_IO_EXTRA_H
#define RVVM_USER_IO_EXTRA_H

#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>

/* These Linux LP64 structures and flags are identical on RV64, ARM64 and
 * x86-64. Passing guest addresses directly leaves fault and partial-result
 * handling, ancillary data and timeout writeback to the host kernel. */
_Static_assert(sizeof(struct iovec) == 16 && offsetof(struct iovec, iov_len) == 8, "RV64 iovec ABI");
_Static_assert(sizeof(struct msghdr) == 56 && offsetof(struct msghdr, msg_namelen) == 8
    && offsetof(struct msghdr, msg_iov) == 16 && offsetof(struct msghdr, msg_iovlen) == 24
    && offsetof(struct msghdr, msg_control) == 32 && offsetof(struct msghdr, msg_controllen) == 40
    && offsetof(struct msghdr, msg_flags) == 48, "RV64 msghdr ABI");
_Static_assert(sizeof(struct mmsghdr) == 64 && offsetof(struct mmsghdr, msg_len) == 56, "RV64 mmsghdr ABI");
_Static_assert(sizeof(struct cmsghdr) == 16 && offsetof(struct cmsghdr, cmsg_level) == 8
    && offsetof(struct cmsghdr, cmsg_type) == 12, "RV64 cmsghdr ABI");
_Static_assert(sizeof(struct timespec) == 16 && offsetof(struct timespec, tv_nsec) == 8, "RV64 timeout ABI");
_Static_assert(SPLICE_F_MOVE == 1 && SPLICE_F_NONBLOCK == 2 && SPLICE_F_MORE == 4
    && SPLICE_F_GIFT == 8, "RV64 splice flags");
_Static_assert(MSG_DONTWAIT == 0x40 && MSG_WAITFORONE == 0x10000
    && MSG_CMSG_CLOEXEC == 0x40000000, "RV64 receive flags");

static long user_io_vmsplice(uintptr_t fd, uintptr_t iov, uintptr_t count, uintptr_t flags)
{
    return errno_ret(USER_SYSCALL(SYS_vmsplice, fd, iov, count, flags, 0, 0));
}

static long user_io_recvmmsg(uintptr_t fd, uintptr_t messages, uintptr_t count,
                           uintptr_t flags, uintptr_t timeout)
{
    return errno_ret(USER_SYSCALL(SYS_recvmmsg, fd, messages, count, flags, timeout, 0));
}
#endif
