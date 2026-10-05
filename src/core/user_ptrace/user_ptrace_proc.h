/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest process identity for a debugger reading its tracee's proc files. */
#ifndef RVVM_USER_PTRACE_PROC_H
#define RVVM_USER_PTRACE_PROC_H

#include <limits.h>

static pid_t user_ptrace_proc_pid(const char* path, const char* leaf)
{
    if (strncmp(path, "/proc/", 6)) return 0;
    const char* number = path + 6;
    if (*number < '0' || *number > '9') return 0;
    char* end;
    unsigned long pid = strtoul(number, &end, 10);
    if (!pid || pid > INT_MAX) return 0;
    if (!strncmp(end, "/task/", 6)) {
        number = end + 6;
        if (*number < '0' || *number > '9') return 0;
        pid = strtoul(number, &end, 10);
        if (!pid || pid > INT_MAX) return 0;
    }
    return *end == '/' && !strcmp(end + 1, leaf) ? (pid_t)pid : 0;
}

// Resolve the link itself, including aliases/dirfds, before classifying it.
// A regular file named /proc/<pid>/exe on a replacement mount is not authority
// to expose a tracee's executable. The ptrace API also checks kernel access.
static bool user_ptrace_proc_exe_inner(int dirfd, const char* path, char* descriptor, size_t size)
{
    char resolved[4096];
    if (!user_proc_resolve(dirfd, path, resolved, sizeof(resolved))) return false;
    pid_t pid = user_ptrace_proc_pid(resolved, "exe");
    if (!pid || user_exe_self(resolved)) return false;
    return user_ptrace_remote_exe_descriptor(pid, descriptor, size);
}

static bool user_ptrace_proc_exe(int dirfd, const char* path, char* descriptor, size_t size)
{
    user_fd_lock();
    bool result = user_ptrace_proc_exe_inner(dirfd, path, descriptor, size);
    user_fd_unlock();
    return result;
}

#endif
