/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_EXE_FD_H
#define RVVM_USER_EXE_FD_H
#include <sys/resource.h>
#ifndef F_DUPFD_QUERY
#define F_DUPFD_QUERY 1027
#endif

// Guest descriptor operations must not expose or close the emulator's pin.
// If dup3 explicitly wants its number, move the pin before honoring dup3.

static long user_exe_same_file(int first, int second)
{
    int same = fcntl(first, F_DUPFD_QUERY, second);
    if (same >= 0) return same;
    if (errno != EINVAL && errno != ENOSYS) return -errno;
    long result = syscall(SYS_kcmp, getpid(), getpid(), 0, (unsigned long)first, (unsigned long)second);
    return result < 0 ? -errno : result == 0;
}

static void user_exe_relocation_commit(bool replaced)
{
    int pin = user_exe_relocation.pin;
    int current = replaced ? pin : user_exe_relocation.target;
    atomic_store_uint32_relax(&user_exe_fd_value, current);
    snprintf(user_exe_descriptor, sizeof(user_exe_descriptor), "/proc/thread-self/fd/%d", current);
    atomic_store_uint32(&user_exe_relocation.recovery_pending, 0);
    atomic_store_uint32(&user_exe_relocation.owner, 0);
    if (!replaced) close(pin);
}

/* Inspect the kernel result rather than replay dup3: another implicit close
 * would release the lender's POSIX locks on the source file. */
static void user_exe_relocation_finish(bool shared_files, uint32_t tid)
{
    uint32_t owner = atomic_load_uint32(&user_exe_relocation.owner);
    if (!owner || (tid && owner != tid)) return;
    if (!shared_files) {
        // The lender cannot inspect a different kernel FD table. Publish the
        // valid spare pin; a surviving holder resolves the operation itself.
        atomic_store_uint32_relax(&user_exe_fd_value, user_exe_relocation.pin);
        snprintf(user_exe_descriptor, sizeof(user_exe_descriptor), "/proc/thread-self/fd/%d", user_exe_fd);
        atomic_store_uint32(&user_exe_relocation.recovery_pending, 1);
        return;
    }
    long same = user_exe_same_file(user_exe_relocation.target, user_exe_relocation.pin);
    if (same < 0) rvvm_fatal("Cannot recover executable-pin relocation: %ld", same);
    // An inherited source can already alias the private pin. Clearing CLOEXEC
    // proves completion even when the open file description did not change.
    int flags = same ? fcntl(user_exe_relocation.target, F_GETFD) : 0;
    if (flags < 0) rvvm_fatal("Cannot inspect executable-pin descriptor flags");
    user_exe_relocation_commit(!same || !(flags & FD_CLOEXEC));
}

static void user_exe_relocation_held(void)
{
    /* The outer descriptor guard serializes publication of these states.
     * Wait slots remain allocated after their first use, so an unlocked
     * blocking waiter cannot make this empty-table check miss recovery. */
    if (!atomic_load_uint32(&user_exe_relocation.owner) && !user_fd_table()->exec_owner
        && !user_fd_table()->wait_slots) return;
    user_fd_mutex_lock(&user_exe_lock);
    user_exe_relocation_finish(true, 0);
    user_fd_waits_reap();
    if (user_fd_table()->exec_owner) {
        /* Successful exec detached the owner's kernel table and discarded
         * its mappings. Restore handoff flags in the surviving table. */
        if (user_exe_fd >= 0) fcntl(user_exe_fd, F_SETFD, FD_CLOEXEC);
        if (user_fd_table()->exec_handoff >= 0) close(user_fd_table()->exec_handoff);
        user_fd_table()->exec_handoff = -1;
        user_fd_table()->exec_owner = 0;
    }
    user_fd_mutex_unlock(&user_exe_lock);
}

static void user_exe_relocation_resume(void)
{
    if (!atomic_load_uint32(&user_exe_relocation.recovery_pending)) return;
    user_fd_lock();
    user_exe_relocation_held();
    user_fd_unlock();
}

static int user_exe_move_pin(void)
{
    if (!user_exe_waits) return fcntl(user_exe_fd, F_DUPFD_CLOEXEC, 0);
    int pin;
    for (;;) {
        // Closed numbers still used by a blocking fcntl cannot receive a
        // readable private pin before the kernel looks up their file. O_PATH
        // placeholders yield EBADF for lock operations, just like closed fds.
        pin = open("/", O_PATH | O_CLOEXEC);
        if (pin < 0) break;
        struct user_fd_wait* wait = user_exe_waits;
        while (wait && wait->fd != pin) wait = wait->next;
        if (wait) { wait->placeholder = pin; continue; }
        if (syscall(SYS_dup3, user_exe_fd, pin, O_CLOEXEC) < 0) {
            int error = errno;
            close(pin);
            errno = error;
            pin = -1;
        }
        break;
    }
    int error = errno;
    for (struct user_fd_wait* wait = user_exe_waits; wait; wait = wait->next) {
        if (wait->placeholder >= 0) close(wait->placeholder);
        wait->placeholder = -1;
    }
    errno = error;
    return pin;
}

static long user_exe_dup3(int oldfd, int newfd, unsigned flags)
{
    if (oldfd == newfd || (flags & ~O_CLOEXEC)) return -EINVAL;
    user_fd_lock();
    user_fd_mutex_lock(&user_exe_lock);
    long ret;
    if (user_private_fd(oldfd)) ret = -EBADF;
    else if (newfd == user_vm_fd) {
        struct rlimit limit;
        if (fcntl(oldfd, F_GETFD) < 0 || getrlimit(RLIMIT_NOFILE, &limit)
            || (unsigned)newfd >= limit.rlim_cur) {
            ret = -EBADF;
            goto out;
        }
        int moved = fcntl(user_vm_fd, F_DUPFD_CLOEXEC, 0);
        if (moved < 0) ret = -errno;
        else {
            ret = errno_ret(syscall(SYS_dup3, oldfd, newfd, flags));
            if (ret < 0) close(moved);
            else atomic_store_uint32_relax(&user_fd_table()->vm_fd, moved);
        }
    }
    else if (newfd != user_exe_fd) ret = errno_ret(syscall(SYS_dup3, oldfd, newfd, flags));
    else {
        struct rlimit limit;
        if (fcntl(oldfd, F_GETFD) < 0 || getrlimit(RLIMIT_NOFILE, &limit)
            || (unsigned)newfd >= limit.rlim_cur) {
            ret = -EBADF;
            goto out;
        }
        ret = user_exe_same_file(user_exe_fd, user_exe_fd);
        if (ret < 0) goto out; // Recovery must be possible before changing the pin.
        int pin = user_exe_move_pin();
        if (pin < 0) ret = -errno;
        else {
            user_exe_relocation.target = newfd;
            user_exe_relocation.pin = pin;
            atomic_store_uint32(&user_exe_relocation.owner, syscall(SYS_gettid));
            ret = errno_ret(syscall(SYS_dup3, oldfd, newfd, flags));
            user_exe_relocation_commit(ret >= 0);
        }
    }
out:
    user_fd_mutex_unlock(&user_exe_lock);
    user_fd_unlock();
    return ret;
}

static long user_exe_fcntl(int fd, int cmd, unsigned long arg)
{
    user_fd_lock();
    if (cmd == F_SETLKW || cmd == F_OFD_SETLKW) {
        user_fd_mutex_lock(&user_exe_lock);
        struct user_fd_wait* wait = user_fd_wait_alloc();
        if (!wait) { user_fd_mutex_unlock(&user_exe_lock); user_fd_unlock(); return -ENOMEM; }
        wait->fd = fd;
        wait->placeholder = -1;
        wait->tid = syscall(SYS_gettid);
        if (user_private_fd(fd) || fcntl(fd, F_GETFD) < 0) {
            user_fd_wait_free(wait);
            user_fd_mutex_unlock(&user_exe_lock);
            user_fd_unlock();
            return -EBADF;
        }
        wait->next = user_exe_waits;
        user_exe_waits = wait;
        user_fd_mutex_unlock(&user_exe_lock);
        // Native lock waits must allow close_range/fork/unshare to proceed.
        // Only pin relocation needs to avoid reusing this descriptor number.
        user_fd_unlock();
        long ret = errno_ret(USER_SYSCALL(SYS_fcntl, fd, cmd, arg, 0, 0, 0));
        user_fd_mutex_lock(&user_exe_lock);
        struct user_fd_wait** link = &user_exe_waits;
        while (*link != wait) link = &(*link)->next;
        *link = wait->next;
        user_fd_wait_free(wait);
        user_fd_mutex_unlock(&user_exe_lock);
        return ret;
    }
    long ret = user_private_fd(fd) ? -EBADF : errno_ret(USER_SYSCALL(SYS_fcntl, fd, cmd, arg, 0, 0, 0));
    user_fd_unlock();
    return ret;
}

static long user_exe_dup(int fd)
{
    user_fd_lock();
    long ret = user_private_fd(fd) ? -EBADF : errno_ret(dup(fd));
    user_fd_unlock();
    return ret;
}

static long user_exe_close(int fd)
{
    user_fd_lock();
    long ret = user_private_fd(fd) ? -EBADF : (long)errno_ret(close(fd));
    user_fd_unlock();
    return ret;
}

#endif
