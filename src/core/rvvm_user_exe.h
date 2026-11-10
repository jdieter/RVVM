/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_EXE_H
#define RVVM_USER_EXE_H

#include <linux/magic.h>

#include "rvvm_user_fd_table.h"
#include "rvvm_user_fs.h"
#define user_exe_fd_value (user_fd_table()->exe_fd)
#define user_exe_fd ((int)atomic_load_uint32_relax(&user_exe_fd_value))
static bool user_private_fd(int fd) { return fd >= 0 && fd == user_exe_fd; }
#define user_exe_descriptor (user_fd_table()->descriptor)
static struct stat user_host_exe;
static struct stat user_host_exe_link;
static THREAD_LOCAL struct stat user_fork_exe_link;
static THREAD_LOCAL bool user_fork_exe_link_ready;
static void user_exe_process_link_init(bool shared)
{
    if (lstat("/proc/self/exe", &user_fork_exe_link))
        memset(&user_fork_exe_link, 0, sizeof(user_fork_exe_link));
    user_fork_exe_link_ready = true;
    if (!shared) user_host_exe_link = user_fork_exe_link;
}
#define user_exe_lock (user_fd_table()->lock)
#define user_exe_waits (user_fd_table()->waits)
#define user_exe_relocation (user_fd_table()->relocation)

static const char* user_exe_path(void)
{
    static THREAD_LOCAL char path[64];
    static THREAD_LOCAL int saved_fd = -1;
    static THREAD_LOCAL pid_t saved_tid;
    int fd = user_exe_fd;
    pid_t tid = user_fd_owner.tid;
    if (!tid) tid = syscall(SYS_gettid);
    // Numeric TID paths address this thread's table after UNSHARE, without
    // resolving the thread-self magic link on every executable operation.
    if (fd != saved_fd || tid != saved_tid) {
        /* Proc may number tasks in an ancestor PID namespace: name this
         * thread as proc does, from its thread-self link. */
        unsigned number = tid;
        char self[64];
        ssize_t n = tid == syscall(SYS_gettid) ? readlink("/proc/thread-self", self, sizeof(self) - 1) : -1;
        if (n > 0) {
            self[n] = 0;
            const char* task = strstr(self, "/task/");
            if (task) number = strtoul(task + 6, NULL, 10);
        }
        snprintf(path, sizeof(path), "/proc/%u/fd/%d", number, fd);
        saved_fd = fd;
        saved_tid = tid;
    }
    return path;
}

#include "rvvm_user_exe_fd.h"

static unsigned user_exe_fd_args(unsigned nr)
{
    unsigned mask = 0;
    switch (nr) {
        case 7: case 10: case 13: case 16: case 21: case 22: case 23:
        case 25: case 27: case 28: case 29: case 32: case 33: case 34:
        case 35: case 37: case 44: case 46: case 47: case 48: case 50:
        case 52: case 53: case 54: case 55: case 56: case 61: case 62:
        case 63: case 64: case 65: case 66: case 67: case 68: case 69: case 70: case 71:
        case 74: case 75: case 76: case 77: case 78: case 79: case 80: case 82: case 83: case 84:
        case 86: case 87: case 88: case 182: case 183: case 185: case 200: case 201: case 202: case 203:
        case 204: case 205: case 206: case 207: case 208: case 209:
        case 210: case 211: case 212: case 213: case 223: case 242: case 243: case 264:
        case 265: case 267: case 269: case 276: case 281: case 285: case 286: case 287:
        case 263: case 451:
        case 291: case 424: case 437: case 439: case 441: case 443: case 452:
            mask = 1;
            break;
    }
    if (nr == 36 || nr == 71 || nr == 77) mask |= 2;
    if (nr == 21 || nr == 37 || nr == 76 || nr == 276 || nr == 285) mask |= 4;
    return mask;
}

static void user_exe_filter_args(long nr, long a[6])
{
    unsigned mask = user_exe_fd_args(nr);
    if (nr == 57) mask |= 1;
    for (unsigned i = 0; i < 3; ++i)
        if ((mask & (1U << i)) && user_private_fd((int)a[i])) {
            // signalfd4(-1) creates a descriptor rather than rejecting it.
            a[i] = nr == 74 ? -2 : -1;
        }
    if (nr == 95 && a[0] == 3 && user_private_fd((int)a[1])) a[1] = -1;
    if (nr == 222 && !(a[3] & 0x20) /* RISC-V MAP_ANONYMOUS */
        && user_private_fd((int)a[4])) a[4] = -1;
}

static bool user_exe_init(const char* path)
{
    extern char** environ;
    int fd = -1;
    /* A self-exec may have no descriptor slots left, including hard NOFILE=0.
     * Reuse the existing private readable pin; the kernel still executes the
     * original path and enforces its permissions. Remove only our first entry,
     * retaining any identically named variables supplied by the guest. */
    const char* marker = environ && environ[0] ? environ[0] : "";
    if (!strncmp(marker, "RVVM_USER_EXEPIN=", 17)) {
        char* end;
        long inherited = strtol(marker + 17, &end, 10);
        struct stat held, target;
        if (end != marker + 17 && !*end && inherited >= 0 && inherited <= INT_MAX
            && !fstat((int)inherited, &held) && !stat(path, &target)
            && held.st_dev == target.st_dev && held.st_ino == target.st_ino
            && (fcntl((int)inherited, F_GETFL) & (O_ACCMODE | O_PATH)) == O_RDONLY
            && fcntl((int)inherited, F_GETFD) == 0) {
            fd = (int)inherited;
            if (fcntl(fd, F_SETFD, FD_CLOEXEC)) return false;
            environ++;
        }
    }
    if (fd < 0) fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    // Keep the pinned guest inode away from normal guest descriptor allocation.
    int pin = fcntl(fd, F_DUPFD_CLOEXEC, 1024);
    if (pin < 0) pin = fcntl(fd, F_DUPFD_CLOEXEC, 64);
    if (pin < 0) pin = fd;
    else close(fd);
    atomic_store_uint32_relax(&user_exe_fd_value, pin);
    snprintf(user_exe_descriptor, sizeof(user_exe_descriptor), "/proc/thread-self/fd/%d", user_exe_fd);
    // Chroots without procfs still execute normally; there is no proc view to replace.
    if (stat("/proc/self/exe", &user_host_exe)) memset(&user_host_exe, 0, sizeof(user_host_exe));
    if (lstat("/proc/self/exe", &user_host_exe_link)) memset(&user_host_exe_link, 0, sizeof(user_host_exe_link));
    return user_exe_fd >= 0;
}

/* A PID parsed from a resolved proc path, numbered as getpid() numbers it.
 * Proc may belong to an ancestor PID namespace, as after unshare -p without
 * a new proc: NSpid then lists the proc's number first, ours last. */
static unsigned user_exe_local_pid(unsigned pid)
{
    char path[48], line[160];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    struct user_proc_reader reader;
    if (!user_proc_open(&reader, path)) return pid;
    unsigned local = pid;
    while (user_proc_line(&reader, line, sizeof(line))) {
        if (strncmp(line, "NSpid:", 6)) continue;
        for (char* at = line + 6;;) {
            while (*at == ' ' || *at == '\t') ++at;
            if (*at < '0' || *at > '9') break;
            local = strtoul(at, &at, 10);
        }
        break;
    }
    user_proc_close(&reader);
    return local;
}

/* Whether a proc path's PID names this process (or, with thread, this
 * thread), however proc numbers it. */
static bool user_proc_is_self(unsigned pid, bool thread)
{
    unsigned self = getpid(), tid = thread ? (unsigned)syscall(SYS_gettid) : self;
    if (pid == self || pid == tid) return true;
    pid = user_exe_local_pid(pid);
    return pid == self || pid == tid;
}

static bool user_exe_self(const char* path)
{
    unsigned pid, tid;
    int end = 0;
    if (sscanf(path, "/proc/%u/exe%n", &pid, &end) == 1 && end && !path[end])
        return user_proc_is_self(pid, true);
    end = 0;
    return sscanf(path, "/proc/%u/task/%u/exe%n", &pid, &tid, &end) == 2
        && end && !path[end] && user_proc_is_self(pid, false);
}

static user_fd_table_t* user_exe_fd_directory(int fd)
{
    char name[64], path[128];
    snprintf(name, sizeof(name), "/proc/thread-self/fd/%d", fd);
    ssize_t n = readlink(name, path, sizeof(path) - 2);
    if (n < 3 || memcmp(path + n - 3, "/fd", 3)) return NULL;
    path[n] = 0;
    if (strncmp(path, "/proc/", 6)) return NULL;
    struct stat st;
    if (fstat(fd, &st) || user_fs_type(st.st_dev) != PROC_SUPER_MAGIC) return NULL;
    unsigned pid, tid;
    int end = 0;
    if (sscanf(path, "/proc/%u/task/%u/fd%n", &pid, &tid, &end) == 2 && end && !path[end]) {
        unsigned self = getpid();
        if (pid != self && user_exe_local_pid(pid) != self) return NULL;
        user_fd_table_t* table = user_fd_table_lookup(tid);
        return table ? table : user_fd_table_lookup(user_exe_local_pid(tid));
    }
    end = 0;
    if (sscanf(path, "/proc/%u/fd%n", &pid, &end) == 1 && end && !path[end]) {
        user_fd_table_t* table = user_fd_table_lookup(pid);
        return table ? table : user_fd_table_lookup(user_exe_local_pid(pid));
    }
    return NULL;
}

static long user_exe_getdents(int fd, void* guest, size_t size)
{
    size = (unsigned int)size; // getdents64's count is 32-bit even on RV64.
    user_fd_table_t* table = user_exe_fd_directory(fd);
    if (!table) return errno_ret(syscall(SYS_getdents64, fd, guest, size));
    char buffer[4096], hidden[16];
    user_fd_mutex_lock(&table->lock);
    snprintf(hidden, sizeof(hidden), "%d", (int)atomic_load_uint32_relax(&table->exe_fd));
    long result;
    do {
        result = errno_ret(syscall(SYS_getdents64, fd, buffer, size < sizeof(buffer) ? size : sizeof(buffer)));
        if (result <= 0) break;
        size_t kept = 0;
        for (size_t pos = 0; pos < (size_t)result;) {
            struct uapi_linux_dirent64* entry = (void*)(buffer + pos);
            size_t length = entry->d_reclen;
            if (strcmp(entry->d_name, hidden)) {
                memmove(buffer + kept, entry, length);
                kept += length;
            }
            pos += length;
        }
        if (kept) {
            int error = uapi_extra_copy(buffer, guest, kept, true);
            result = error ? error : (long)kept;
            break;
        }
    } while (true); // A buffer containing only the hidden entry is not EOF.
    user_fd_mutex_unlock(&table->lock);
    user_fd_table_release(table);
    return result;
}

static bool user_exe_cached_link(int dirfd, const char* path)
{
    // The common proc link (including directory aliases) has a stable identity.
    // Keep kernel path resolution: a normal symlink named "exe" is not special.
    struct stat st;
    const struct stat* identity = user_fork_exe_link_ready ? &user_fork_exe_link : &user_host_exe_link;
    if (!identity->st_ino) {
        if (!user_fork_exe_link_ready) {
            if (lstat("/proc/self/exe", &user_fork_exe_link))
                memset(&user_fork_exe_link, 0, sizeof(user_fork_exe_link));
            user_fork_exe_link_ready = true;
        }
        identity = &user_fork_exe_link;
    }
    int ret = -1;
    if (identity->st_ino) {
#if defined(__linux__) && defined(__aarch64__) && defined(__AARCH64EL__)
        ret = uapi_stat_syscall(SYS_newfstatat, dirfd, (long)path, (long)&st, AT_SYMLINK_NOFOLLOW);
#else
        ret = fstatat(dirfd, path, &st, AT_SYMLINK_NOFOLLOW);
#endif
    }
    return !ret && st.st_dev == identity->st_dev && st.st_ino == identity->st_ino;
}

// Inspect the link itself, so dirfd and proc/self aliases are resolved by Linux.
static bool user_proc_resolve(int dirfd, const char* path, char* resolved, size_t size)
{
    int fd = openat(dirfd, path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    char descriptor[64];
    snprintf(descriptor, sizeof(descriptor), "/proc/thread-self/fd/%d", fd);
    ssize_t length = readlink(descriptor, resolved, size - 1);
    struct stat st;
    bool proc = length >= 6 && !memcmp(resolved, "/proc/", 6)
        && !fstat(fd, &st) && user_fs_type(st.st_dev) == PROC_SUPER_MAGIC;
    close(fd);
    if (!proc || length == size - 1) return false;
    resolved[length] = 0;
    return true;
}

static bool user_exe_link_held(int dirfd, const char* path)
{
    char resolved[4096];
    return user_proc_resolve(dirfd, path, resolved, sizeof(resolved)) && user_exe_self(resolved);
}

static bool user_exe_link(int dirfd, const char* path)
{
    // This probe opens no temporary descriptor, so needs no range-close guard.
    if (user_exe_cached_link(dirfd, path)) return true;
    user_fd_lock();
    bool result = user_exe_link_held(dirfd, path);
    user_fd_unlock();
    return result;
}

static bool user_exe_fast_open(const char* path, unsigned long flags, long* result)
{
    // Only ordinary read opens of this exact spelling qualify. Other paths,
    // flags and openat2 constraints retain the resolved-descriptor check.
    if (user_exe_fd < 0 || (flags & ~(O_CLOEXEC | O_NONBLOCK | O_LARGEFILE))) return false;
    if (!user_path_match(path, "/proc/self/exe")
        || !user_exe_cached_link(AT_FDCWD, "/proc/self/exe")) return false;
    user_fd_lock();
    // Pin writers also hold this guard; the generated path is private TLS.
    *result = errno_ret(USER_SYSCALL(SYS_openat, AT_FDCWD, user_exe_path(), flags, 0, 0, 0));
    user_fd_unlock();
    return true;
}

static long user_exe_opened(long fd, unsigned long flags, const struct stat* st)
{
    if (user_exe_fd < 0 || st->st_dev != user_host_exe.st_dev || st->st_ino != user_host_exe.st_ino)
        return fd;
    // Reopen rather than dup: guest file offsets and status flags must be independent.
    user_fd_lock();
    int replacement = open(user_exe_path(), flags & ~O_NOFOLLOW);
    long result = replacement < 0 ? -errno : replacement;
    close(fd);
    user_fd_unlock();
    return result;
}

#endif
