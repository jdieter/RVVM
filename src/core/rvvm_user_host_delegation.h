/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_HOST_DELEGATION_H
#define RVVM_USER_HOST_DELEGATION_H

#include <linux/keyctl.h>
#include <linux/mount.h>

/* Linux assigned these numbers across the supported 64-bit architectures.
 * Older libc headers must not hide a syscall implemented by the host kernel. */
#ifndef SYS_quotactl_fd
#define SYS_quotactl_fd 443
#endif
#ifndef SYS_statmount
#define SYS_statmount 457
#endif
#ifndef SYS_listmount
#define SYS_listmount 458
#endif
#ifndef SYS_lsm_get_self_attr
#define SYS_lsm_get_self_attr 459
#endif
#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules 461
#endif
#ifndef SYS_lsm_set_self_attr
#define SYS_lsm_set_self_attr 460
#endif
#ifndef SYS_open_tree
#define SYS_open_tree 428
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#define SYS_fspick 433
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

static void user_host_path(char* snapshot, char* wrapped, const char** path)
{
    if (*path && user_internal_proc_path(wrapped, *path)) { *path = wrapped; return; }
    if (!prefix_path || !*prefix_path || !*path) return;
    long ret = user_path_copy(snapshot, *path, UAPI_PATH_MAX);
    /* Hand bad paths to Linux as bad paths, rather than returning before its
     * capability, flag and descriptor checks. Neither sentinel can succeed. */
    if (ret == -EFAULT) { *path = (const char*)1; return; }
    if (ret == -ENAMETOOLONG) { *path = snapshot; return; }
    if (snapshot[0] == '/' && !path_bypass(snapshot)
        && strlen(prefix_path) + (size_t)ret >= UAPI_PATH_MAX) {
        memset(wrapped, 'x', UAPI_PATH_MAX);
        *path = wrapped;
        return;
    }
    *path = wrap_path(wrapped, snapshot);
}

/* Use a positive closed descriptor: some APIs distinguish negative argument
 * validation from a descriptor lookup failure. Let Linux order those checks. */
static int user_host_fd(int fd) { return user_private_fd(fd) ? INT_MAX : fd; }

static no_inline long user_host_path_call(unsigned nr, uintptr_t a0, uintptr_t a1,
                                        uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    char snapshot[2][UAPI_PATH_MAX], wrapped[2][UAPI_PATH_MAX];
    const char* path = (const char*)a0;
    const char* second = (const char*)a1;
    unsigned path_arg = 0;
    switch (nr) {
        case SYS_open_tree: case SYS_fspick: case SYS_mount_setattr:
        case SYS_move_mount: path_arg = 1; path = (const char*)a1; break;
    }
    user_host_path(snapshot[0], wrapped[0], &path);
    if (nr == SYS_move_mount || nr == SYS_pivot_root) {
        second = (const char*)(nr == SYS_move_mount ? a3 : a1);
        user_host_path(snapshot[1], wrapped[1], &second);
        if (nr == SYS_move_mount) a3 = (uintptr_t)second;
        else a1 = (uintptr_t)second;
    }
    if (path_arg) a1 = (uintptr_t)path;
    else a0 = (uintptr_t)path;
    user_fd_lock();
    if (path_arg) a0 = user_host_fd((int)a0);
    if (nr == SYS_move_mount) a2 = user_host_fd((int)a2);
    long ret = errno_ret(USER_SYSCALL(nr, a0, a1, a2, a3, a4, 0));
    user_fd_unlock();
    return ret;
}

static no_inline long user_host_fsconfig(int fd, unsigned cmd, const char* key,
                                        const void* value, int aux)
{
    char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
    const char* path = value;
    /* Only PATH commands unambiguously carry a pathname. STRING and BINARY
     * remain filesystem-specific data, including strings beginning with '/'. */
    bool pathname = cmd == FSCONFIG_SET_PATH || cmd == FSCONFIG_SET_PATH_EMPTY;
    if (pathname && fd >= 0 && key && value && (aux == AT_FDCWD || aux >= 0)) {
        user_host_path(snapshot, wrapped, &path);
        value = path;
    }
    user_fd_lock();
    fd = user_host_fd(fd);
    if (pathname || cmd == FSCONFIG_SET_FD) aux = user_host_fd(aux);
    long ret = errno_ret(USER_SYSCALL(SYS_fsconfig, fd, cmd, key, value, aux, 0));
    user_fd_unlock();
    return ret;
}

static long user_host_fd_call(unsigned nr, int fd, uintptr_t a1, uintptr_t a2)
{
    user_fd_lock();
    long ret = errno_ret(USER_SYSCALL(nr, user_host_fd(fd), a1, a2, 0, 0, 0));
    user_fd_unlock();
    return ret;
}

static no_inline long user_host_mount_setattr(int fd, const char* path, unsigned flags,
                                             const void* attr, size_t size)
{
    user_fd_lock();
    long ret;
    void* copy = NULL;
    /* Keep Linux's size, flag, capability and bad-buffer error ordering.
     * A complete snapshot also preserves future extension-tail validation. */
    if (!(flags & ~(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT))
        && size >= 32 && size <= (size_t)sysconf(_SC_PAGESIZE)) {
        copy = user_runtime_allocate(size);
        if (!copy) { user_fd_unlock(); return -ENOMEM; }
        if (user_memory_copy(copy, attr, size)) {
            user_runtime_release(copy); copy = NULL; attr = (const void*)1;
        }
    }
    if (copy) {
        struct mount_attr* request = copy;
        if ((request->attr_set & MOUNT_ATTR_IDMAP) && request->userns_fd <= INT_MAX)
            request->userns_fd = user_host_fd((int)request->userns_fd);
        if (request->attr_set || request->attr_clr || request->propagation)
            ret = user_host_path_call(SYS_mount_setattr, fd, (uintptr_t)path, flags, (uintptr_t)copy, size);
        else /* A no-op must not dereference even an invalid pathname. */
            ret = errno_ret(USER_SYSCALL(SYS_mount_setattr, user_host_fd(fd), path, flags, copy, size, 0));
    } else {
        ret = errno_ret(USER_SYSCALL(SYS_mount_setattr, user_host_fd(fd), path, flags, attr, size, 0));
    }
    user_runtime_release(copy);
    user_fd_unlock();
    return ret;
}

static long user_host_keyctl(uintptr_t command, uintptr_t a1, uintptr_t a2,
                            uintptr_t a3, uintptr_t a4)
{
    /* WATCH_KEY is the only current keyctl command taking a descriptor.
     * Freeze pin relocation until the kernel has resolved that descriptor.
     * Other commands interpret this argument as data, not a descriptor. */
    if ((unsigned)command == KEYCTL_WATCH_KEY) {
        user_fd_lock();
        if (user_private_fd((int)a2)) a2 = -1;
        long ret = errno_ret(USER_SYSCALL(SYS_keyctl, command, a1, a2, a3, a4, 0));
        user_fd_unlock();
        return ret;
    }
    return errno_ret(USER_SYSCALL(SYS_keyctl, command, a1, a2, a3, a4, 0));
}

static no_inline long user_host_quotactl(uintptr_t command, const char* special,
                                       uintptr_t id, uintptr_t data)
{
    char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
    if (prefix_path && *prefix_path && special) {
        long ret = user_path_copy(snapshot, special, sizeof(snapshot));
        if (ret < 0) return ret;
        if (snapshot[0] == '/' && !path_bypass(snapshot)
            && strlen(prefix_path) + (size_t)ret >= sizeof(wrapped)) return -ENAMETOOLONG;
        special = wrap_path(wrapped, snapshot);
    }
    /* RV64 and ARM64 share the LP64 quota UAPI. Leave validation, permission
     * checks and buffer copies with the kernel, including inaccessible pages. */
    return errno_ret(USER_SYSCALL(SYS_quotactl, command, special, id, data, 0, 0));
}

static long user_host_quotactl_fd(int fd, uintptr_t command, uintptr_t id, uintptr_t data)
{
    user_fd_lock();
    if (user_private_fd(fd)) fd = -1;
    long ret = errno_ret(USER_SYSCALL(SYS_quotactl_fd, fd, command, id, data, 0, 0));
    user_fd_unlock();
    return ret;
}
#endif
