/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_EXEC_H
#define RVVM_USER_EXEC_H

static long user_exec_environment(char** envp, char* marker, char*** result)
{
    size_t count = 0, limit = (size_t)sysconf(_SC_ARG_MAX) / sizeof(char*);
    char* entry;
    if (envp) {
        for (;;) {
            if (count >= limit) return -E2BIG;
            if (user_memory_copy(&entry, envp + count, sizeof(entry))) return -EFAULT;
            if (!entry) break;
            count++;
        }
    }
    char** next_env = malloc((count + 2) * sizeof(char*));
    if (!next_env) return -ENOMEM;
    if (count && user_memory_copy(next_env + 1, envp, count * sizeof(char*))) {
        free(next_env);
        return -EFAULT;
    }
    next_env[0] = marker;
    next_env[count + 1] = NULL;
    *result = next_env;
    return 0;
}

static long user_execve(const char* path, char** argv, char** envp)
{
    user_fd_lock();
    user_fd_mutex_lock(&user_exe_lock);
    int pin = user_exe_fd;
    /* The kernel's proc link names the host interpreter, not the guest ELF. */
    if (pin >= 0 && user_exe_link_held(AT_FDCWD, path)) path = user_exe_path();
    struct stat held, target;
    long ret;
    if (pin < 0 || fstat(pin, &held) || stat(path, &target)
        || held.st_dev != target.st_dev || held.st_ino != target.st_ino) {
        ret = errno_ret(USER_SYSCALL(SYS_execve, path, argv, envp, 0, 0, 0));
        goto out;
    }
    char** next_env;
    char marker[64];
    snprintf(marker, sizeof(marker), "RVVM_USER_EXEPIN=%d", pin);
    ret = user_exec_environment(envp, marker, &next_env);
    if (ret) goto out;
    user_fd_table()->exec_owner = syscall(SYS_gettid);
    if (fcntl(pin, F_SETFD, 0)) ret = -errno;
    else {
        ret = errno_ret(USER_SYSCALL(SYS_execve, path, argv, next_env, 0, 0, 0));
        fcntl(pin, F_SETFD, FD_CLOEXEC);
    }
    user_fd_table()->exec_owner = 0;
    free(next_env);
out:
    user_fd_mutex_unlock(&user_exe_lock);
    user_fd_unlock();
    return ret;
}

/* binfmt_misc cannot reopen ELF paths through CLOEXEC file/directory fds.
 * Keep a separate ELF descriptor alive until the next RVVM loads it;
 * never change the guest descriptor's flags. */
static long user_execveat_inner(int fd, const char* path, char** argv, char** envp, int flags)
{
    long ret = errno_ret(USER_SYSCALL(SYS_execveat, fd, path, argv, envp, flags, 0));
    char first;
    if (ret != -ENOENT || user_memory_copy(&first, path, 1)
        || first == '/' || fd == AT_FDCWD
        || !(fcntl(fd, F_GETFD) & FD_CLOEXEC)
        || (!first && !(flags & AT_EMPTY_PATH))) return ret;

    int handoff = first ? openat(fd, path, O_RDONLY | O_CLOEXEC
                                    | ((flags & AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0))
                        : fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (handoff < 0) return ret;
    user_fd_table()->exec_owner = syscall(SYS_gettid);
    user_fd_table()->exec_handoff = handoff;
    char name[64];
    snprintf(name, sizeof(name), "/proc/thread-self/fd/%d", handoff);
    int reader = open(name, O_RDONLY | O_CLOEXEC);
    unsigned char header[20];
    ssize_t n = reader < 0 ? -1 : pread(reader, header, sizeof(header), 0);
    if (reader >= 0) close(reader);
    /* Leave scripts and other architectures to the kernel, including the
     * intentional ENOENT for a CLOEXEC script descriptor. */
    if (n != sizeof(header) || memcmp(header, "\177ELF\2\1\1", 7)
        || header[18] != 243 || header[19] != 0) goto out;

    char** next_env;
    char marker[64];
    snprintf(marker, sizeof(marker), "RVVM_USER_EXECFD=%d", handoff);
    ret = user_exec_environment(envp, marker, &next_env);
    if (ret) goto out;
    if (fcntl(handoff, F_SETFD, 0)) ret = -errno;
    else {
        ret = errno_ret(USER_SYSCALL(SYS_execveat, handoff, "", argv, next_env,
                                    flags | AT_EMPTY_PATH, 0));
    }
    free(next_env);
out:
    close(handoff);
    user_fd_table()->exec_handoff = -1;
    user_fd_table()->exec_owner = 0;
    return ret;
}

static long user_execveat(int fd, const char* path, char** argv, char** envp, int flags)
{
    user_fd_lock();
    long result = user_execveat_inner(fd, path, argv, envp, flags);
    user_fd_unlock();
    return result;
}

static void user_exec_handoff_close(const char* path)
{
    extern char** environ;
    if (!environ || !environ[0] || strncmp(environ[0], "RVVM_USER_EXECFD=", 17)) return;
    const char* marker = environ[0] + 17;
    char* end;
    long fd = strtol(marker, &end, 10);
    char expected[64];
    snprintf(expected, sizeof(expected), "/dev/fd/%ld", fd);
    /* Only consume our own exact binfmt invocation, after loading and pinning
     * the executable. Ordinary inherited guest descriptors remain open. */
    if (*marker && !*end && fd >= 0 && fd <= INT_MAX && !strcmp(path, expected)) {
        close((int)fd);
        environ++;
    }
}
#endif
