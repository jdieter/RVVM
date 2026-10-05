/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_EXTRA_H
#define RVVM_USER_EXTRA_H

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/sem.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <asm/sembuf.h>
#include "rvvm_user_flags.h"

/* RV64 and the supported hosts use LP64 little-endian Linux ABIs. */
struct uapi_extra_epoll_event {
    uint32_t events;
    uint32_t padding;
    uint64_t data;
};

struct uapi_semid64_ds {
    struct ipc64_perm perm;
    int64_t otime, ctime;
    uint64_t nsems, unused[2];
};

_Static_assert(sizeof(long) == 8 && sizeof(void*) == 8, "LP64 required");
_Static_assert(sizeof(struct timespec) == 16, "64-bit timespec required");
_Static_assert(sizeof(struct mq_attr) == 64, "RV64 mq_attr layout");
_Static_assert(sizeof(struct ipc64_perm) == 48, "RV64 ipc64_perm layout");
_Static_assert(offsetof(struct ipc64_perm, mode) == 20, "IPC mode offset");
_Static_assert(offsetof(struct ipc64_perm, seq) == 24, "IPC sequence offset");
_Static_assert(sizeof(struct uapi_semid64_ds) == 88, "RV64 semid64_ds layout");
_Static_assert(IPC_SET == 1 && IPC_STAT == 2 && SEM_STAT == 18 && SEM_STAT_ANY == 20,
               "Linux semaphore commands");

static inline long uapi_extra_result(long ret)
{
    return ret == -1 ? -errno : ret;
}

/* Copy through the kernel, rather than dereferencing untrusted guest memory.
 * Partial transfers are EFAULT, matching syscall buffer semantics. */
static inline int uapi_extra_copy(void* local, void* guest, size_t size, bool to_guest)
{
    struct iovec l = { local, size }, r = { guest, size };
    // The TGID's leader may have exited while this thread still owns its mm.
    pid_t tid = syscall(SYS_gettid);
    ssize_t ret = to_guest ? process_vm_writev(tid, &l, 1, &r, 1, 0)
                          : process_vm_readv(tid, &l, 1, &r, 1, 0);
    return ret < 0 ? -errno : (ret == (ssize_t)size ? 0 : -EFAULT);
}

static inline long uapi_extra_prctl(int option, unsigned long a, unsigned long b,
                                  unsigned long c, unsigned long d)
{
    switch (option) {
        // These Linux operations describe the real task and share the RV64 ABI.
        // Do not forward architecture, address-layout or host TLS controls.
        case PR_SET_PDEATHSIG: case PR_GET_PDEATHSIG:
        case PR_GET_DUMPABLE: case PR_SET_DUMPABLE:
        case PR_GET_KEEPCAPS: case PR_SET_KEEPCAPS:
        case PR_GET_TIMING: case PR_SET_TIMING:
        case PR_SET_NAME: case PR_GET_NAME:
        case PR_CAPBSET_READ: case PR_CAPBSET_DROP:
        case PR_GET_SECUREBITS: case PR_SET_SECUREBITS:
        case PR_SET_TIMERSLACK: case PR_GET_TIMERSLACK:
        case PR_SET_CHILD_SUBREAPER: case PR_GET_CHILD_SUBREAPER:
        case PR_SET_NO_NEW_PRIVS: case PR_GET_NO_NEW_PRIVS:
        case PR_CAP_AMBIENT:
        case PR_SET_PTRACER:
            return uapi_extra_result(syscall(SYS_prctl, option, a, b, c, d));
        case PR_SET_SECCOMP: case PR_GET_SECCOMP:
            return -EINVAL;
        default:
            return -EINVAL;
    }
}

static inline long uapi_extra_mq_open(const char* name, uint32_t flags, unsigned mode, void* attr)
{
    // Raw mq_open takes a name without the slash required by libc mq_open.
    return uapi_extra_result(syscall(SYS_mq_open, name, uapi_open_flags_to_host(flags), mode, attr));
}

static inline long uapi_extra_fanotify_init(unsigned flags, uint32_t event_flags)
{
    return uapi_extra_result(syscall(SYS_fanotify_init, flags, uapi_open_flags_to_host(event_flags)));
}

static inline long uapi_extra_open_by_handle_at(int mountfd, void* handle, uint32_t flags)
{
    return uapi_extra_result(syscall(SYS_open_by_handle_at, mountfd, handle, uapi_open_flags_to_host(flags)));
}

static inline long uapi_extra_semctl(int id, int num, int cmd, uintptr_t arg)
{
    // IPC_64 is the historical version bit; leave it intact for the kernel.
    int operation = cmd & ~0x100;
    if (operation != IPC_SET && operation != IPC_STAT && operation != SEM_STAT && operation != SEM_STAT_ANY)
        return uapi_extra_result(syscall(SYS_semctl, id, num, cmd, arg));

    struct semid64_ds host = {0};
    struct uapi_semid64_ds guest = {0};
    if (operation == IPC_SET) {
        int ret = uapi_extra_copy(&guest, (void*)arg, sizeof(guest), false);
        if (ret) return ret;
        host.sem_perm = guest.perm;
    }
    long ret = uapi_extra_result(syscall(SYS_semctl, id, num, cmd, &host));
    if (ret >= 0 && operation != IPC_SET) {
        guest.perm = host.sem_perm;
        guest.otime = host.sem_otime;
        guest.ctime = host.sem_ctime;
        guest.nsems = host.sem_nsems;
        int copied = uapi_extra_copy(&guest, (void*)arg, sizeof(guest), true);
        if (copied) return copied;
    }
    return ret;
}

static inline long uapi_extra_epoll_pwait2(int fd, void* events, int maxevents,
                                          const void* timeout, const void* mask, size_t masksize)
{
#ifdef SYS_epoll_pwait2
    if (maxevents <= 0 || maxevents > INT_MAX / (int)sizeof(struct uapi_extra_epoll_event)) return -EINVAL;
    struct epoll_event* host = malloc((size_t)maxevents * sizeof(*host));
    if (!host) return -ENOMEM;
    long ret = uapi_extra_result(syscall(SYS_epoll_pwait2, fd, host, maxevents, timeout, mask, masksize));
    if (ret > 0) {
        struct uapi_extra_epoll_event* guest = calloc((size_t)ret, sizeof(*guest));
        if (!guest) {
            ret = -ENOMEM;
        } else {
            for (long i = 0; i < ret; ++i) {
                guest[i].events = host[i].events;
                guest[i].data = host[i].data.u64;
            }
            int copied = uapi_extra_copy(guest, events, (size_t)ret * sizeof(*guest), true);
            if (copied) ret = copied;
            free(guest);
        }
    }
    free(host);
    return ret;
#else
    (void)fd; (void)events; (void)maxevents; (void)timeout; (void)mask; (void)masksize;
    return -ENOSYS;
#endif
}

static inline long uapi_extra_execveat(int fd, const char* path, void* argv, void* envp, uint32_t flags)
{
#ifdef SYS_execveat
    static const struct uapi_flag_map at_flags[] = {
        { 0x100, 0x100, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW },
        { 0x1000, 0x1000, AT_EMPTY_PATH, AT_EMPTY_PATH },
    };
    return uapi_extra_result(syscall(SYS_execveat, fd, path, argv, envp,
        uapi_translate_flags(flags, at_flags, sizeof(at_flags) / sizeof(at_flags[0]), true)));
#else
    (void)fd; (void)path; (void)argv; (void)envp; (void)flags;
    return -ENOSYS;
#endif
}

#endif
