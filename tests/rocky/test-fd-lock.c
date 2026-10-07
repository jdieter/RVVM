/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/futex.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "util/spinlock.h"
#include "util/utils.h"

static long errno_ret(long ret) { return ret == -1 ? -errno : ret; }
static void user_ptrace_set_exe_fd_pointer(uint32_t* fd) { (void)fd; }
#include "core/rvvm_user_fd_table.h"
#define user_exe_fd ((int)atomic_load_uint32_relax(&user_fd_table()->exe_fd))
#define user_vm_fd ((int)atomic_load_uint32_relax(&user_fd_table()->vm_fd))
static bool user_private_fd(int fd) { return fd >= 0 && (fd == user_exe_fd || fd == user_vm_fd); }
#define user_exe_fd_value (user_fd_table()->exe_fd)
#define user_exe_lock (user_fd_table()->lock)
#define user_exe_descriptor (user_fd_table()->descriptor)
#define user_exe_waits (user_fd_table()->waits)
#define user_exe_relocation (user_fd_table()->relocation)

static atomic_int entered, pause_entry;
static long test_syscall(long nr, int fd, int cmd, unsigned long arg, long a3, long a4, long a5)
{
    if (cmd == F_OFD_SETLKW) {
        atomic_store(&entered, 1);
        while (atomic_load(&pause_entry)) sched_yield();
    }
    return syscall(nr, fd, cmd, arg, a3, a4, a5);
}
#define USER_SYSCALL test_syscall
static atomic_int close_entered;
static int pause_close = -1;
static int test_close(int fd)
{
    if (fd == pause_close) {
        atomic_store(&close_entered, 1);
        for (;;) syscall(SYS_futex, &close_entered, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
    return syscall(SYS_close, fd);
}
#define close test_close
static atomic_int dup_entered;
static int pause_dup = -1;
static bool before_dup;
static long test_fd_syscall(long nr, ...)
{
    if (nr == SYS_gettid) return syscall(nr);
    va_list args;
    va_start(args, nr);
    if (nr == SYS_kcmp) {
        int first = va_arg(args, int), second = va_arg(args, int), kind = va_arg(args, int);
        unsigned long a = va_arg(args, unsigned long), b = va_arg(args, unsigned long);
        va_end(args);
        return syscall(nr, first, second, kind, a, b);
    }
    assert(nr == SYS_dup3);
    int source = va_arg(args, int), target = va_arg(args, int);
    unsigned flags = va_arg(args, unsigned);
    va_end(args);
    if (before_dup && target == pause_dup) {
        atomic_store(&dup_entered, 1);
        for (;;) syscall(SYS_futex, &dup_entered, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
    long ret = syscall(nr, source, target, flags);
    if (!before_dup && ret >= 0 && target == pause_dup) {
        atomic_store(&dup_entered, 1);
        for (;;) syscall(SYS_futex, &dup_entered, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
    return ret;
}
#define syscall test_fd_syscall
#include "core/rvvm_user_exe_fd.h"
#undef syscall
#undef close

static void* waiter(void* fd)
{
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    return (void*)user_exe_fcntl(*(int*)fd, F_OFD_SETLKW, (unsigned long)&lock);
}

static void start_waiter(pthread_t* thread, int* fd)
{
    atomic_store(&entered, 0);
    assert(!pthread_create(thread, NULL, waiter, fd));
    while (!atomic_load(&entered)) sched_yield();
}

static void test_close_range(void)
{
    char path[] = "/tmp/rvvm-ofd.XXXXXX";
    int holder = mkstemp(path), fd = open(path, O_RDWR);
    assert(holder >= 0 && fd >= 0 && !unlink(path));
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    assert(!fcntl(holder, F_OFD_SETLK, &lock));
    pthread_t thread;
    start_waiter(&thread, &fd);
    // Closing the description that owns the lock must unblock the waiter.
    assert(!user_fd_close_range(holder, holder, 0));
    void* result;
    assert(!pthread_join(thread, &result) && (long)result == 0);
    assert(!user_exe_waits && !close(fd));
}

static void test_closed_reservation(int minimum)
{
    char path[] = "/tmp/rvvm-reserved.XXXXXX";
    int file = mkstemp(path), fd = fcntl(file, F_DUPFD_CLOEXEC, minimum);
    assert(file >= 0 && fd >= 0 && !unlink(path));
    int source = open("/dev/null", O_RDONLY);
    int original = fcntl(source, F_DUPFD_CLOEXEC, 64);
    assert(source >= 0 && original >= 64);
    user_exe_fd_value = original;
    atomic_store(&pause_entry, 1);
    pthread_t thread;
    start_waiter(&thread, &fd);
    assert(!user_fd_close_range(fd, fd, 0));
    assert(user_exe_dup3(source, original, 0) == original);
    assert(user_exe_fd != fd && user_exe_fd < 128);
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    atomic_store(&pause_entry, 0);
    void* result;
    assert(!pthread_join(thread, &result) && (long)result == -EBADF);
    assert(!user_exe_waits);
    int pin = user_exe_fd;
    assert(!close(pin) && !close(original) && !close(source) && !close(file));
    user_exe_fd_value = UINT32_MAX;
}

static void test_allocation_failure(void)
{
    int source = open("/dev/null", O_RDONLY), fd = dup(source);
    int original = fcntl(source, F_DUPFD_CLOEXEC, 64);
    assert(source >= 0 && fd >= 0 && original >= 64);
    user_exe_fd_value = original;
    atomic_store(&pause_entry, 1);
    pthread_t thread;
    start_waiter(&thread, &fd);
    assert(!user_fd_close_range(fd, fd, 0));
    struct rlimit saved, limit;
    assert(!getrlimit(RLIMIT_NOFILE, &saved));
    limit = saved;
    limit.rlim_cur = original + 1;
    assert(!setrlimit(RLIMIT_NOFILE, &limit));
    int occupied[128], count = 0, next;
    while ((next = open("/dev/null", O_RDONLY)) >= 0) {
        assert(count < 128);
        occupied[count++] = next;
    }
    assert(errno == EMFILE);
    assert(user_exe_dup3(-1, original, 0) == -EBADF);
    assert(user_exe_dup3(original + 1, original, 0) == -EBADF);
    assert(!close(fd)); // Leave only the reserved slot free, with a valid target.
    assert(user_exe_dup3(source, original, 0) == -EMFILE);
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF); // No placeholder leaked.
    assert(user_exe_fd == original && fcntl(original, F_GETFD) == FD_CLOEXEC);
    assert(!setrlimit(RLIMIT_NOFILE, &saved));
    for (int i = 0; i < count; ++i) if (occupied[i] != fd) assert(!close(occupied[i]));
    limit.rlim_cur = fd + 1;
    assert(!setrlimit(RLIMIT_NOFILE, &limit));
    assert(user_exe_dup3(source, original, 0) == -EBADF);
    assert(!setrlimit(RLIMIT_NOFILE, &saved));
    atomic_store(&pause_entry, 0);
    void* result;
    assert(!pthread_join(thread, &result) && (long)result == -EBADF);
    assert(!user_exe_waits && !close(source) && !close(original));
    user_exe_fd_value = UINT32_MAX;
}

static int killed_closer(void* opaque)
{
    user_fd_guard_child();
    return user_exe_close(*(int*)opaque);
}

static void test_killed_close(void)
{
    int fd = open("/dev/null", O_RDONLY);
    assert(fd >= 0);
    void* stack = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    assert(stack != MAP_FAILED);
    pause_close = fd;
    pid_t child = clone(killed_closer, (char*)stack + (1 << 20),
                        CLONE_VM | CLONE_FILES | SIGCHLD, &fd);
    assert(child > 0);
    while (!atomic_load(&close_entered)) sched_yield();
    assert(!kill(child, SIGKILL));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    // A different owner must never be released; the verified dead child may.
    user_fd_mutex_recover(&user_exe_lock, child + 1);
    assert((user_exe_lock.owner & 0x7FFFFFFFU) == (unsigned)child);
    user_fd_mutex_recover(&user_exe_lock, child);
    user_fd_guard_recover(child);
    user_fd_waits_remove(user_fd_table(), child);
    pause_close = -1;
    assert(!user_exe_close(fd));
    user_fd_lock();
    user_fd_unlock();
    assert(!munmap(stack, 1 << 20));
}

static int killed_duplicator(void* opaque)
{
    user_fd_guard_child();
    return user_exe_dup3(*(int*)opaque, pause_dup, 0);
}

static void test_killed_relocation(bool completed, bool shared_files, bool alias)
{
    char path[] = "/tmp/rvvm-killed-pin.XXXXXX";
    char source_path[] = "/tmp/rvvm-locked-source.XXXXXX";
    int file = mkstemp(path), source = mkstemp(source_path);
    assert(file >= 0 && source >= 0 && !unlink(path) && !unlink(source_path));
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    assert(!fcntl(source, F_SETLK, &lock));
    int original = fcntl(file, F_DUPFD_CLOEXEC, 64);
    assert(original >= 64);
    user_exe_fd_value = original;
    if (alias) { assert(!close(source)); source = dup(file); assert(source >= 0); }
    struct stat expected, actual;
    assert(!fstat(original, &expected));
    void* stack = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    assert(stack != MAP_FAILED);
    pause_dup = original;
    before_dup = !completed;
    atomic_store(&dup_entered, 0);
    pid_t child = clone(killed_duplicator, (char*)stack + (1 << 20),
                        CLONE_VM | (shared_files ? CLONE_FILES : 0) | SIGCHLD, &source);
    assert(child > 0);
    while (!atomic_load(&dup_entered)) sched_yield();
    assert(!kill(child, SIGKILL));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    pause_dup = -1;
    assert(user_exe_relocation.owner == (unsigned)child);
    // A different child's lender must not touch this operation or its spare.
    user_exe_relocation_finish(shared_files, child + 1);
    assert(user_exe_relocation.owner == (unsigned)child);
    assert(fcntl(user_exe_relocation.pin, F_GETFD) == FD_CLOEXEC);
    user_exe_relocation_finish(shared_files, child);
    user_fd_mutex_recover(&user_exe_lock, child);
    user_fd_guard_recover(child);
    if (!shared_files) {
        // Simulate the next syscall in a surviving holder, whose kernel table
        // still contains the old pin when the killed borrower's table differed.
        assert(user_exe_relocation.recovery_pending);
        user_exe_relocation_resume();
    }
    assert(!fstat(user_exe_fd, &actual));
    assert(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
    assert(!user_exe_relocation.owner);
    assert((user_exe_fd != original) == (completed && shared_files));
    pid_t probe = fork();
    assert(probe >= 0);
    if (!probe) _exit(fcntl(source, F_SETLK, &lock) == 0 ? 1 : 0);
    assert(waitpid(probe, &status, 0) == probe && WIFEXITED(status));
    if (!alias) assert(!WEXITSTATUS(status));
    if (user_exe_fd != original) assert(!close(user_exe_fd));
    assert(!close(original) && !close(source) && !close(file));
    user_exe_fd_value = UINT32_MAX;
    assert(!munmap(stack, 1 << 20));
}

static atomic_int survivor_go, survivor_pid;
static void* survivor_stack;
static struct stat survivor_expected;
static int surviving_holder(void* unused)
{
    (void)unused;
    while (!atomic_load(&survivor_go))
        syscall(SYS_futex, &survivor_go, FUTEX_WAIT, 0, NULL, NULL, 0);
    user_fd_guard_child();
    // A holder can have sampled recovery_pending before blocking on the dead owner's
    // guard. Acquiring it must resolve the operation before any FD mutation.
    user_fd_lock();
    struct stat actual;
    int result = fstat(user_exe_fd, &actual) || actual.st_dev != survivor_expected.st_dev
        || actual.st_ino != survivor_expected.st_ino || user_exe_relocation.owner;
    user_fd_unlock();
    return result;
}

static int private_duplicator(void* source)
{
    int child = clone(surviving_holder, (char*)survivor_stack + (1 << 20),
                      CLONE_VM | CLONE_FILES | SIGCHLD, NULL);
    if (child < 0) return 1;
    atomic_store(&survivor_pid, child);
    return killed_duplicator(source);
}

static void test_private_survivor(void)
{
    assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
    char path[] = "/tmp/rvvm-private-pin.XXXXXX";
    int file = mkstemp(path), source = open("/dev/null", O_RDONLY);
    int original = fcntl(file, F_DUPFD_CLOEXEC, 64);
    assert(file >= 0 && source >= 0 && original >= 64 && !unlink(path));
    assert(!fstat(original, &survivor_expected));
    user_exe_fd_value = original;
    void* stack = mmap(NULL, 2 << 20, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    assert(stack != MAP_FAILED);
    survivor_stack = (char*)stack + (1 << 20);
    atomic_store(&dup_entered, 0);
    before_dup = false;
    pause_dup = original;
    pid_t child = clone(private_duplicator, (char*)stack + (1 << 20), CLONE_VM | SIGCHLD, &source);
    assert(child > 0);
    while (!atomic_load(&dup_entered)) sched_yield();
    assert(!kill(child, SIGKILL));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    pause_dup = -1;
    user_exe_relocation_finish(false, child);
    user_fd_mutex_recover(&user_exe_lock, child);
    user_fd_guard_recover(child);
    assert(user_exe_relocation.recovery_pending);
    atomic_store(&survivor_go, 1);
    syscall(SYS_futex, &survivor_go, FUTEX_WAKE, 1, NULL, NULL, 0);
    assert(waitpid(atomic_load(&survivor_pid), &status, 0) > 0);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    struct stat actual;
    assert(!fstat(original, &actual) && actual.st_ino == survivor_expected.st_ino);
    assert(!close(original) && !close(source) && !close(file));
    user_exe_fd_value = UINT32_MAX;
    assert(!munmap(stack, 2 << 20) && !prctl(PR_SET_CHILD_SUBREAPER, 0));
}

int main(void)
{
    user_fd_guard_set_resume(user_exe_relocation_held);
    test_close_range();
    test_closed_reservation(0);
    test_closed_reservation(128); // A high reservation must not hide low free slots.
    test_allocation_failure();
    test_killed_close();
    test_killed_relocation(false, true, false);
    test_killed_relocation(true, true, false);
    test_killed_relocation(true, true, true);
    test_private_survivor();
    puts("PASS blocking fcntl/close_range, descriptor limits and killed-child lock recovery");
}
