/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_EXEC_H
#define RVVM_USER_EXEC_H

static long user_exec_interpreter(const char* path, char** argv, char** envp)
{
    char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
    long ret = user_path_copy(snapshot, path, sizeof(snapshot));
    if (ret < 0) return ret;
    if (USER_SYSCALL(SYS_faccessat, AT_FDCWD, wrap_path(wrapped, snapshot), F_OK, 0, 0, 0)) return -ENOENT;
    char* next[256] = {"/proc/self/exe", "-user", (char*)path};
    char* first;
    if (user_memory_copy(&first, argv, sizeof(first))) return -EFAULT;
    for (size_t i = 1; first && i < 253; ++i) {
        if (user_memory_copy(&next[i + 2], argv + i, sizeof(*argv))) return -EFAULT;
        if (!next[i + 2]) break;
    }
    return errno_ret(USER_SYSCALL(SYS_execve, "/proc/self/exe", next, envp, 0, 0, 0));
}

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
    char** next_env = user_runtime_allocate((count + 2) * sizeof(char*));
    if (!next_env) return -ENOMEM;
    if (count && user_memory_copy(next_env + 1, envp, count * sizeof(char*))) {
        user_runtime_release(next_env);
        return -EFAULT;
    }
    next_env[0] = marker;
    next_env[count + 1] = NULL;
    *result = next_env;
    return 0;
}

/* Exec replaces the emulator too. Carry immutable filter snapshots as private
 * environment entries, consumed before building the next guest's stack. Each
 * entry stays below Linux's per-string exec limit even for 4096 instructions.
 * RVVM process emulation is not a security boundary against native execution. */
#define USER_SECCOMP_MARKER "RVVM_USER_SECCOMP="
#define USER_SECCOMP_END "RVVM_USER_SECCOMP_END=1"

static long user_seccomp_environment(char** envp, char*** result, size_t* owned)
{
    *result = envp;
    *owned = 0;
    if (!user_seccomp) return 0;
    char** copy;
    long ret = user_exec_environment(envp, NULL, &copy);
    if (ret) return ret;
    size_t count = 0, filters = 0;
    while (copy[count + 1]) count++;
    for (struct user_seccomp_filter* f = user_seccomp; f; f = f->prev) filters++;
    char** next = user_runtime_allocate((filters + count + 2) * sizeof(*next));
    if (!next) { user_runtime_release(copy); return -ENOMEM; }
    memcpy(next + filters + 1, copy + 1, (count + 1) * sizeof(*next));
    user_runtime_release(copy);
    next[filters] = USER_SECCOMP_END;
    static const char hex[] = "0123456789abcdef";
    size_t slot = filters;
    for (struct user_seccomp_filter* f = user_seccomp; f; f = f->prev) {
        size_t bytes = f->count * sizeof(*f->insns), prefix = sizeof(USER_SECCOMP_MARKER) - 1;
        char* entry = user_runtime_allocate(prefix + bytes * 2 + 1);
        if (!entry) {
            for (size_t i = slot; i < filters; i++) user_runtime_release(next[i]);
            user_runtime_release(next);
            return -ENOMEM;
        }
        memcpy(entry, USER_SECCOMP_MARKER, prefix);
        const unsigned char* data = (const unsigned char*)f->insns;
        for (size_t i = 0; i < bytes; i++) {
            entry[prefix + i * 2] = hex[data[i] >> 4];
            entry[prefix + i * 2 + 1] = hex[data[i] & 15];
        }
        entry[prefix + bytes * 2] = 0;
        next[--slot] = entry; // Restore oldest first to preserve stacking order.
    }
    *result = next;
    *owned = filters;
    return 0;
}

static void user_seccomp_environment_free(char** envp, size_t owned)
{
    if (!owned) return;
    for (size_t i = 0; i < owned; i++) user_runtime_release(envp[i]);
    user_runtime_release(envp);
}

static bool user_seccomp_restore(void)
{
    extern char** environ;
    const size_t prefix = sizeof(USER_SECCOMP_MARKER) - 1;
    if (!environ || !environ[0] || strncmp(environ[0], USER_SECCOMP_MARKER, prefix)) return true;
    while (environ[0] && !strncmp(environ[0], USER_SECCOMP_MARKER, prefix)) {
        const char* hex = environ[0] + prefix;
        size_t length = strlen(hex);
        if (!length || length % (sizeof(struct sock_filter) * 2)
            || length > BPF_MAXINSNS * sizeof(struct sock_filter) * 2) return false;
        struct sock_filter* insns = user_runtime_allocate(length / 2);
        if (!insns) return false;
        for (size_t i = 0; i < length; i++) {
            unsigned value = hex[i] >= '0' && hex[i] <= '9' ? hex[i] - '0'
                : hex[i] >= 'a' && hex[i] <= 'f' ? hex[i] - 'a' + 10 : 16;
            if (value == 16) { user_runtime_release(insns); return false; }
            if (i % 2) ((unsigned char*)insns)[i / 2] |= value;
            else ((unsigned char*)insns)[i / 2] = value << 4;
        }
        struct sock_fprog prog = {length / (2 * sizeof(*insns)), insns};
        long ret = user_seccomp_install(0, &prog);
        user_runtime_release(insns);
        if (ret) return false;
        environ++;
    }
    if (!environ[0] || strcmp(environ[0], USER_SECCOMP_END)) return false;
    environ++;
    return true;
}

static long user_execve_inner(const char* path, char** argv, char** envp)
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
    user_runtime_release(next_env);
out:
    user_fd_mutex_unlock(&user_exe_lock);
    user_fd_unlock();
    return ret;
}

static long user_execve(const char* path, char** argv, char** envp)
{
    char** next;
    size_t owned;
    long ret = user_seccomp_environment(envp, &next, &owned);
    if (ret) return ret;
    ret = user_execve_inner(path, argv, next);
    user_seccomp_environment_free(next, owned);
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
    user_runtime_release(next_env);
out:
    close(handoff);
    user_fd_table()->exec_handoff = -1;
    user_fd_table()->exec_owner = 0;
    return ret;
}

static long user_execveat(int fd, const char* path, char** argv, char** envp, int flags)
{
    char** next;
    size_t owned;
    long result = user_seccomp_environment(envp, &next, &owned);
    if (result) return result;
    user_fd_lock();
    result = user_execveat_inner(fd, path, argv, next, flags);
    user_fd_unlock();
    user_seccomp_environment_free(next, owned);
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
