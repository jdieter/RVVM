/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_OBSERVER_H
#define RVVM_USER_OBSERVER_H

/* Only the trusted worker calls this protocol. The observer owns its files
 * and limits, and never executes a guest operation or borrows libc TLS. */
struct user_observer {
    user_fd_mutex_t lock;
    uint32_t state, alive;
    pid_t owner, pid, caller;
    long result;
    int operation;
    struct user_native_vfork* request;
    void* stack;
    void* marker;
    size_t marker_size;
    int root, maps, smaps, owner_fd, children, cookie;
    /* Pinned proc numbers PIDs in its mount's namespace, which may be an
     * ancestor of the active one; owner_proc is the owner's PID there. */
    bool nested;
    unsigned long owner_proc;
    struct stat identity;
    char input[4096], line[256];
};
static struct user_observer* user_observer;
static struct user_native_vfork* user_native_requests;

static long user_observer_raw(long nr, long a, long b, long c, long d, long e, long f)
{
    return user_native_internal(nr, a, b, c, d, e, f);
}

static unsigned long user_observer_number(const char** text, unsigned base)
{
    unsigned long number = 0;
    for (;;) {
        unsigned digit = (unsigned char)**text;
        digit = digit >= '0' && digit <= '9' ? digit - '0'
              : digit >= 'a' && digit <= 'f' ? digit - 'a' + 10 : 255;
        if (digit >= base) break;
        number = number * base + digit;
        ++*text;
    }
    return number;
}

static void user_observer_decimal(char* output, unsigned long value)
{
    char reverse[24];
    size_t count = 0;
    do { reverse[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) *output++ = reverse[--count];
    *output = 0;
}

static bool user_observer_map_identity(const char* line, struct user_observer* observer)
{
    /* start-end perms offset major:minor inode */
    const char* at = line;
    user_observer_number(&at, 16);
    if (*at++ != '-') return false;
    user_observer_number(&at, 16);
    while (*at == ' ') ++at;
    for (unsigned i = 0; i < 4 && *at; ++i) ++at;
    while (*at == ' ') ++at;
    user_observer_number(&at, 16);
    while (*at == ' ') ++at;
    unsigned major_id = user_observer_number(&at, 16);
    if (*at++ != ':') return false;
    unsigned minor_id = user_observer_number(&at, 16);
    while (*at == ' ') ++at;
    unsigned long inode = user_observer_number(&at, 10);
    return inode == observer->identity.st_ino
        && major_id == major(observer->identity.st_dev)
        && minor_id == minor(observer->identity.st_dev);
}

static bool user_observer_lines(struct user_observer* observer, int fd, bool cow)
{
    if (user_observer_raw(SYS_lseek, fd, 0, SEEK_SET, 0, 0, 0) < 0) return false;
    size_t used = 0;
    bool selected = false;
    long count;
    while ((count = user_observer_raw(SYS_read, fd, (long)observer->input,
                                      sizeof(observer->input), 0, 0, 0)) > 0) {
        for (long i = 0; i < count; ++i) {
            char byte = observer->input[i];
            if (byte != '\n') {
                if (used + 1 < sizeof(observer->line)) observer->line[used++] = byte;
                continue;
            }
            observer->line[used] = 0;
            if (user_observer_map_identity(observer->line, observer)) {
                if (!cow) return true;
                selected = true;
            } else if (cow && selected) {
                const char* at = observer->line;
                user_observer_number(&at, 16);
                if (*at == '-') selected = false;
                if ((!memcmp(observer->line, "Shared_Dirty:", 13)
                     || !memcmp(observer->line, "Shared_Clean:", 13))) {
                    at = observer->line + 13;
                    while (*at == ' ') ++at;
                    if (user_observer_number(&at, 10)) return true;
                }
            }
            used = 0;
        }
    }
    return false;
}

/* Read a numeric status/fdinfo field below the pinned proc root. For NSpid,
 * first is the proc mount's namespace and last the task's active one. */
static bool user_observer_field(struct user_observer* observer, const char* path, const char* field,
                                unsigned long* first, unsigned long* last, unsigned* count)
{
    int fd = user_observer_raw(SYS_openat, observer->root, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return false;
    size_t length = strlen(field), used = 0;
    bool found = false;
    long bytes;
    while (!found && (bytes = user_observer_raw(SYS_read, fd, (long)observer->input,
                                                sizeof(observer->input), 0, 0, 0)) > 0) {
        for (long i = 0; i < bytes && !found; ++i) {
            char byte = observer->input[i];
            if (byte != '\n') {
                if (used + 1 < sizeof(observer->line)) observer->line[used++] = byte;
                continue;
            }
            observer->line[used] = 0;
            used = 0;
            if (memcmp(observer->line, field, length)) continue;
            found = true;
            *count = 0;
            for (const char* at = observer->line + length;;) {
                while (*at == ' ' || *at == '\t') ++at;
                if (*at < '0' || *at > '9') break;
                unsigned long value = user_observer_number(&at, 10);
                if (!(*count)++) *first = value;
                *last = value;
            }
        }
    }
    user_observer_raw(SYS_close, fd, 0, 0, 0, 0, 0);
    return found && *count;
}

/* Proc-namespace PID to the active namespace, the one gettid() reports. */
static unsigned long user_observer_active_pid(struct user_observer* observer, unsigned long pid)
{
    if (!observer->nested) return pid;
    char path[48];
    user_observer_decimal(path, pid);
    memcpy(path + strlen(path), "/status", 8);
    unsigned long first, last;
    unsigned count;
    return user_observer_field(observer, path, "NSpid:", &first, &last, &count) ? last : 0;
}

/* Active-namespace caller TID to proc numbering: scan the owner's tasks. */
static unsigned long user_observer_proc_tid(struct user_observer* observer, unsigned long tid)
{
    if (!observer->nested) return tid;
    if (!observer->owner_proc) return 0;
    char path[64];
    user_observer_decimal(path, observer->owner_proc);
    size_t base = strlen(path);
    memcpy(path + base, "/task", 6);
    int dir = user_observer_raw(SYS_openat, observer->root, (long)path,
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (dir < 0) return 0;
    char entries[2048];
    unsigned long found = 0;
    long bytes;
    while (!found && (bytes = user_observer_raw(SYS_getdents64, dir, (long)entries,
                                                sizeof(entries), 0, 0, 0)) > 0) {
        for (long at = 0; at < bytes && !found;) {
            /* linux_dirent64: d_reclen at 16, d_name at 19. */
            const char* name = entries + at + 19;
            unsigned short length;
            memcpy(&length, entries + at + 16, sizeof(length));
            if (!length) break;
            at += length;
            if (*name < '1' || *name > '9') continue;
            const char* digits = name;
            unsigned long candidate = user_observer_number(&digits, 10);
            path[base] = '/';
            memcpy(path + base + 1, "task/", 5);
            user_observer_decimal(path + base + 6, candidate);
            memcpy(path + strlen(path), "/status", 8);
            unsigned long first, last;
            unsigned count;
            if (user_observer_field(observer, path, "NSpid:", &first, &last, &count) && last == tid)
                found = candidate;
        }
    }
    user_observer_raw(SYS_close, dir, 0, 0, 0, 0, 0);
    return found;
}

static bool user_observer_internal_pid(struct user_observer* observer, unsigned pid)
{
    if (pid == (unsigned)observer->pid) return true;
    /* The trusted worker holds mmap_lock: membership and helper creation
     * cannot change until this snapshot witness has been accepted. */
    for (struct user_native_vfork* item = user_native_requests; item; item = item->observer_next) {
        if (item == observer->request) continue;
        if (pid == atomic_load_uint32(item->clone_marker)
            || pid == atomic_load_uint32(&item->helper_pid)) return true;
    }
    return false;
}

/* Returns the candidate's active-namespace PID, or zero. */
static unsigned user_observer_candidate(struct user_observer* observer, unsigned pid)
{
    unsigned active = user_observer_active_pid(observer, pid);
    if (!active || user_observer_internal_pid(observer, active)) return 0;
    char path[48];
    user_observer_decimal(path, pid);
    size_t length = strlen(path);
    memcpy(path + length, "/maps", 6);
    int maps = user_observer_raw(SYS_openat, observer->root, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (maps < 0) return false;
    bool found = user_observer_lines(observer, maps, false);
    user_observer_raw(SYS_close, maps, 0, 0, 0, 0, 0);
    return found ? active : 0;
}

static long user_observer_find(struct user_observer* observer)
{
    if (observer->request->private_thread)
        return user_observer_lines(observer, observer->smaps, true) ? 1 : 0;
    long ret = user_observer_raw(SYS_lseek, observer->children, 0, SEEK_SET, 0, 0, 0);
    if (ret < 0) return ret;
    /* Maps parsing reuses input; stream the child list through its own
     * buffer so large families don't impose a PID-count ceiling. */
    char children[4096];
    unsigned pid = 0;
    while ((ret = user_observer_raw(SYS_read, observer->children, (long)children, sizeof(children), 0, 0, 0)) > 0) {
        for (long i = 0; i < ret; ++i) {
            unsigned digit = (unsigned char)children[i];
            if (digit >= '0' && digit <= '9') {
                digit -= '0';
                if (pid > (UINT32_MAX - digit) / 10) return -EIO;
                pid = pid * 10 + digit;
            } else {
                if (digit != ' ') return -EIO;
                unsigned active = pid ? user_observer_candidate(observer, pid) : 0;
                if (active) return active;
                pid = 0;
            }
        }
    }
    if (ret < 0) return ret;
    return pid ? user_observer_candidate(observer, pid) : 0;
}

static void user_observer_cookie_close(struct user_observer* observer)
{
    if (observer->children >= 0) user_observer_raw(SYS_close, observer->children, 0, 0, 0, 0, 0);
    if (observer->marker) user_observer_raw(SYS_munmap, (long)observer->marker, observer->marker_size, 0, 0, 0, 0);
    if (observer->cookie >= 0) user_observer_raw(SYS_close, observer->cookie, 0, 0, 0, 0, 0);
    observer->children = observer->cookie = -1;
    observer->marker = NULL;
}

static long user_observer_cookie_open(struct user_observer* observer)
{
    observer->cookie = user_observer_raw(SYS_memfd_create, (long)"rvvm-snapshot", MFD_CLOEXEC, 0, 0, 0, 0);
    if (observer->cookie < 0) return observer->cookie;
    long ret = user_observer_raw(SYS_ftruncate, observer->cookie, observer->marker_size, 0, 0, 0, 0);
    if (ret < 0) return ret;
    ret = user_observer_raw(SYS_fstat, observer->cookie, (long)&observer->identity, 0, 0, 0, 0);
    if (ret < 0) return ret;
    ret = user_observer_raw(SYS_mmap, 0, observer->marker_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE, observer->cookie, 0);
    if (ret < 0 && ret >= -4095) return ret;
    observer->marker = (void*)ret;
    *(volatile unsigned char*)observer->marker = 1;
    ret = user_observer_raw(SYS_madvise, ret, observer->marker_size, MADV_UNMERGEABLE, 0, 0, 0);
    if (ret < 0) return ret;
    ret = user_observer_raw(SYS_mprotect, (long)observer->marker, observer->marker_size, PROT_READ, 0, 0, 0);
    if (ret < 0) return ret;
    unsigned long caller = user_observer_proc_tid(observer, observer->caller);
    if (!caller) return -ESRCH;
    char path[64];
    user_observer_decimal(path, caller);
    size_t length = strlen(path);
    memcpy(path + length, "/task/", 6);
    user_observer_decimal(path + length + 6, caller);
    length = strlen(path);
    memcpy(path + length, "/children", 10);
    observer->children = user_observer_raw(SYS_openat, observer->root, (long)path,
                                          O_RDONLY | O_CLOEXEC, 0, 0, 0);
    return observer->children < 0 ? observer->children : 0;
}

static __attribute__((no_stack_protector)) int user_observer_main(void* opaque)
{
    struct user_observer* observer = opaque;
    uint64_t mask = UINT64_MAX;
    user_observer_raw(SYS_rt_sigprocmask, SIG_SETMASK, (long)&mask, 0, 8, 0, 0);
    long ret = user_observer_raw(SYS_setsid, 0, 0, 0, 0, 0, 0);
    if (ret >= 0) ret = user_observer_raw(SYS_close_range, 0, UINT32_MAX, 0, 0, 0, 0);
    if (ret >= 0) ret = observer->root = user_observer_raw(SYS_openat, AT_FDCWD, (long)"/proc", O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (ret >= 0) ret = observer->maps = user_observer_raw(SYS_openat, observer->root, (long)"self/maps", O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (ret >= 0) ret = observer->smaps = user_observer_raw(SYS_openat, observer->root, (long)"self/smaps", O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (ret >= 0) ret = observer->owner_fd = user_observer_raw(SYS_pidfd_open, observer->owner, 0, 0, 0, 0, 0);
    if (ret >= 0) {
        /* A single NSpid level proves proc numbers match gettid(). Without
         * NSpid support, keep the identity mapping. */
        unsigned long first, last;
        unsigned count;
        observer->nested = user_observer_field(observer, "self/status", "NSpid:", &first, &last, &count)
            && count > 1;
        char path[48];
        memcpy(path, "self/fdinfo/", 12);
        user_observer_decimal(path + 12, observer->owner_fd);
        if (observer->nested && user_observer_field(observer, path, "Pid:", &first, &last, &count))
            observer->owner_proc = first;
    }
    observer->result = ret < 0 ? ret : 0;
    atomic_store_uint32(&observer->state, 2);
    user_observer_raw(SYS_futex, (long)&observer->state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    if (ret < 0) return 1;
    for (;;) {
        uint32_t state = atomic_load_uint32(&observer->state);
        if (state == 3) break;
        if (state != 1) {
            struct pollfd owner = {.fd = observer->owner_fd, .events = POLLIN};
            struct timespec timeout = {.tv_sec = 1};
            if (user_observer_raw(SYS_ppoll, (long)&owner, 1, (long)&(struct timespec){0}, 0, 8, 0) > 0) break;
            user_observer_raw(SYS_futex, (long)&observer->state, FUTEX_WAIT_PRIVATE, state, (long)&timeout, 0, 0);
            continue;
        }
        if (observer->operation == 1) observer->result = user_observer_cookie_open(observer);
        else if (observer->operation == 2) observer->result = user_observer_find(observer);
        else { user_observer_cookie_close(observer); observer->result = 0; }
        atomic_store_uint32(&observer->state, 2);
        user_observer_raw(SYS_futex, (long)&observer->state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    }
    user_observer_cookie_close(observer);
    return 0;
}

/* The observer is not the guest's child: a raw intermediate creates it and
 * exits, so it reparents to the nearest subreaper or init. Guest __WALL and
 * __WCLONE waits therefore neither block on it nor lose ECHILD. Until one
 * party reaps the exiting intermediate, guest waits hide its PID. */
static uint32_t user_observer_transient;

static __attribute__((no_stack_protector)) int user_observer_spawn(void* opaque)
{
    struct user_observer* observer = opaque;
    struct {
        uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
    } args = {
        .flags = CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
        .parent_tid = (uintptr_t)&observer->pid,
        .child_tid = (uintptr_t)&observer->alive,
        .stack = (uintptr_t)observer->stack,
        .stack_size = 1024 * 1024 - 2 * sizeof(uintptr_t),
    };
    long ret = user_native_clone3(&args, sizeof(args));
    if (ret < 0) {
        observer->result = ret;
        atomic_store_uint32(&observer->alive, 0);
    }
    return 0;
}

/* Returns true when a guest wait result names the intermediate. A reaping
 * waiter consumes the record: the kernel gives that PID to one reaper only. */
static bool user_observer_hidden(pid_t pid, bool reaped)
{
    if (pid <= 0) return false;
    uint32_t transient = atomic_load_uint32(&user_observer_transient);
    if ((uint32_t)pid != transient) return false;
    if (reaped) atomic_cas_uint32(&user_observer_transient, transient, 0);
    else sched_yield();
    return true;
}

static void user_observer_stop(struct user_observer* observer)
{
    atomic_store_uint32(&observer->state, 3);
    rvvm_futex_wake(&observer->state, 1);
    while (atomic_load_uint32(&observer->alive))
        rvvm_futex_wait(&observer->alive, atomic_load_uint32(&observer->alive), 10000000);
    /* CHILD_CLEARTID runs after the observer's last user stack access. */
    munmap(observer->stack, 1024 * 1024);
    observer->stack = NULL;
}

static void user_observer_join(struct user_observer* observer)
{
    user_observer_stop(observer);
    free(observer);
}

static user_fd_mutex_t user_observer_init_lock;
static void user_observer_fork_child(void)
{
    /* No original actor survives in this mm; its inherited stack and client
     * locks are private copies, even if a parent worker held them at fork. */
    if (user_observer) {
        munmap(user_observer->stack, 1024 * 1024);
        free(user_observer);
    }
    user_observer = NULL;
    user_native_requests = NULL;
    user_observer_transient = 0;
    user_observer_init_lock = (user_fd_mutex_t){0};
}

static struct user_observer* user_observer_get(void)
{
    user_fd_mutex_lock(&user_observer_init_lock);
    pid_t owner = getpid();
    if (user_observer && user_observer->owner != owner) {
        /* These are private copies after ordinary fork. The original actor
         * still owns its parent's mm and must not receive child requests. */
        munmap(user_observer->stack, 1024 * 1024);
        free(user_observer);
        user_observer = NULL;
        user_native_requests = NULL;
    }
    if (user_observer && !atomic_load_uint32(&user_observer->alive)) {
        /* Stopped before a failed exec, or died. A racing caller may still
         * hold the old record; it fails with EIO instead of a dangling use. */
        if (user_observer->stack) user_observer_stop(user_observer);
        user_observer = NULL;
    }
    if (!user_observer) {
        struct user_observer* observer = calloc(1, sizeof(*observer));
        if (!observer) { user_fd_mutex_unlock(&user_observer_init_lock); return NULL; }
        observer->root = observer->maps = observer->smaps = observer->owner_fd = -1;
        observer->children = observer->cookie = -1;
        observer->owner = owner;
        observer->marker_size = user_vma_page();
        const size_t spawn_size = 65536;
        observer->stack = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void* spawn_stack = mmap(NULL, spawn_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (observer->stack == MAP_FAILED || spawn_stack == MAP_FAILED) {
            int error = errno;
            if (observer->stack != MAP_FAILED) munmap(observer->stack, 1024 * 1024);
            if (spawn_stack != MAP_FAILED) munmap(spawn_stack, spawn_size);
            free(observer); user_fd_mutex_unlock(&user_observer_init_lock); errno = error; return NULL;
        }
        uintptr_t* packet = (void*)((char*)observer->stack + 1024 * 1024 - 2 * sizeof(uintptr_t));
        packet[0] = (uintptr_t)user_observer_main;
        packet[1] = (uintptr_t)observer;
        packet = (void*)((char*)spawn_stack + spawn_size - 2 * sizeof(uintptr_t));
        packet[0] = (uintptr_t)user_observer_spawn;
        packet[1] = (uintptr_t)observer;
        observer->alive = UINT32_MAX;
        struct {
            uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
        } args = {
            /* Shared files avoid a second table copy; the intermediate
             * opens nothing, and the observer copies then closes them all. */
            .flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_PARENT_SETTID,
            .parent_tid = (uintptr_t)&user_observer_transient,
            .stack = (uintptr_t)spawn_stack,
            .stack_size = spawn_size - 2 * sizeof(uintptr_t),
        };
        /* Neither new process may run a guest or emulator signal handler on
         * the borrowed TLS before the observer blocks every signal. */
        uint64_t all = UINT64_MAX, saved_mask;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &all, &saved_mask, 8);
        /* An init or subreaper guest would adopt the orphan as an ordinary
         * SIGCHLD child. A direct exit_signal-0 child is visible only to its
         * __WALL/__WCLONE waits: keep that remaining gap instead. */
        int subreaper = 0;
        long ret = getpid() == 1 || (!prctl(PR_GET_CHILD_SUBREAPER, &subreaper) && subreaper)
            ? user_observer_spawn(observer) : user_native_clone3(&args, sizeof(args));
        if (ret > 0) {
            long reaped;
            int status;
            do reaped = user_native_internal(SYS_wait4, ret, (long)&status, __WALL, 0, 0, 0);
            while (reaped == -EINTR);
            /* A racing guest __WALL waiter may have reaped it and cleared
             * the record already; otherwise this reaper owns that duty. */
            if (reaped == ret) atomic_cas_uint32(&user_observer_transient, ret, 0);
        }
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
        munmap(spawn_stack, spawn_size);
        if (ret < 0 || (observer->result < 0 && !observer->pid)) {
            if (ret >= 0) ret = observer->result;
            munmap(observer->stack, 1024 * 1024); free(observer);
            user_fd_mutex_unlock(&user_observer_init_lock); errno = -ret; return NULL;
        }
        while (atomic_load_uint32(&observer->state) != 2 && atomic_load_uint32(&observer->alive))
            rvvm_futex_wait(&observer->state, 0, 10000000);
        ret = observer->result;
        if (ret < 0 || !atomic_load_uint32(&observer->alive)) {
            user_observer_join(observer);
            user_fd_mutex_unlock(&user_observer_init_lock); errno = ret < 0 ? -ret : EIO; return NULL;
        }
        atomic_store_uint32(&observer->state, 0);
        user_observer = observer;
    }
    struct user_observer* result = user_observer;
    user_fd_mutex_unlock(&user_observer_init_lock);
    return result;
}

/* Exec replaces this mm while the observer would keep the old one alive;
 * exit should not leave it running until its next owner pidfd poll. Stop it
 * only while idle: a worker may hold it indefinitely for a stopped child,
 * and exec/exit must not wait for that. A busy observer still exits once the
 * owner pidfd reports the last thread's exit. */
static void user_observer_release(bool wait)
{
    user_fd_mutex_lock(&user_observer_init_lock);
    struct user_observer* observer = user_observer;
    if (observer && observer->owner == getpid() && atomic_cas_uint32(&observer->state, 0, 3)) {
        rvvm_futex_wake(&observer->state, 1);
        while (wait && atomic_load_uint32(&observer->alive))
            rvvm_futex_wait(&observer->alive, atomic_load_uint32(&observer->alive), 10000000);
    }
    user_fd_mutex_unlock(&user_observer_init_lock);
}

static long user_observer_call(struct user_observer* observer, int operation)
{
    observer->operation = operation;
    atomic_store_uint32(&observer->state, 1);
    rvvm_futex_wake(&observer->state, 1);
    while (atomic_load_uint32(&observer->state) != 2) {
        if (!atomic_load_uint32(&observer->alive)) return -EIO;
        rvvm_futex_wait(&observer->state, 1, 10000000);
    }
    long result = observer->result;
    atomic_store_uint32(&observer->state, 0);
    return result;
}

#endif
