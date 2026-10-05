/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FS_WATCH_H
#define RVVM_USER_FS_WATCH_H

#include <stdint.h>
#include <sys/fanotify.h>
#include <sys/syscall.h>

#ifndef SYS_cachestat
#define SYS_cachestat 451
#endif

struct user_cachestat_range { uint64_t off, len; };
struct user_cachestat { uint64_t cached, dirty, writeback, evicted, recently_evicted; };
_Static_assert(sizeof(struct user_cachestat_range) == 16 && sizeof(struct user_cachestat) == 40,
               "Linux cachestat fixed-width ABI");
_Static_assert(FAN_MARK_ADD == 1 && FAN_MARK_REMOVE == 2 && FAN_MARK_FLUSH == 0x80,
               "RV64 fanotify mark flags");

static no_inline long user_fs_fanotify_mark(uintptr_t fd, uintptr_t flags, uint64_t mask,
                                 intptr_t dirfd, const char* pathname)
{
    char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
    if (prefix_path && *prefix_path && pathname && !(flags & FAN_MARK_FLUSH)) {
        long ret = user_path_copy(snapshot, pathname, sizeof(snapshot));
        if (ret < 0) return ret;
        pathname = wrap_path(wrapped, snapshot);
    }
    /* All supported hosts use the native 64-bit mask argument, not the
     * split argument convention of 32-bit fanotify_mark. */
    return errno_ret(syscall(SYS_fanotify_mark, fd, flags, mask, dirfd, pathname));
}

static long user_fs_cachestat(uintptr_t fd, uintptr_t range, uintptr_t result, uintptr_t flags)
{
    /* Fixed-width UAPI fields need no conversion. Kernel copy_to_user also
     * preserves EFAULT handling for read-only and page-crossing buffers. */
    return errno_ret(syscall(SYS_cachestat, fd, range, result, flags));
}
#endif
