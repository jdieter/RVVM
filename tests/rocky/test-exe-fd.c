/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "util/user_fd_guard.h"
#include "util/utils.h"

static atomic_int pin_value;
#define user_exe_fd atomic_load(&pin_value)
#define user_exe_fd_value pin_value
static char user_exe_descriptor[64];
struct user_fd_wait { struct user_fd_wait* next; int fd, placeholder; pid_t tid; };
static struct user_fd_wait* user_exe_waits;
static struct { int target, pin; uint32_t recovery_pending, owner; } user_exe_relocation;
static pthread_mutex_t user_exe_lock = PTHREAD_MUTEX_INITIALIZER;
#define user_fd_mutex_lock pthread_mutex_lock
#define user_fd_mutex_unlock pthread_mutex_unlock
#define atomic_store_uint32_relax atomic_store
static atomic_int lock_waiting;
static long test_fcntl_syscall(long nr, int fd, int cmd, unsigned long arg, long a3, long a4, long a5)
{
    if (cmd == F_OFD_SETLKW) atomic_store(&lock_waiting, 1);
    return syscall(nr, fd, cmd, arg, a3, a4, a5);
}
#define USER_SYSCALL test_fcntl_syscall
static long errno_ret(long result) { return result == -1 ? -errno : result; }

static pthread_mutex_t pause_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pause_cond = PTHREAD_COND_INITIALIZER;
static int paused_fd = -1, closing, released;
static atomic_int started;
static int host_close(int fd)
{
    if (fd == paused_fd) {
        pthread_mutex_lock(&pause_lock);
        closing = 1;
        pthread_cond_broadcast(&pause_cond);
        while (!released) pthread_cond_wait(&pause_cond, &pause_lock);
        pthread_mutex_unlock(&pause_lock);
    }
    return syscall(SYS_close, fd);
}
#define close host_close
#include "core/rvvm_user_exe_fd.h"
#undef close

static void* closer(void* opaque)
{
    atomic_store(&started, 1);
    return (void*)user_exe_close(*(int*)opaque);
}

static void* flag_setter(void* opaque)
{
    atomic_store(&started, 1);
    return (void*)user_exe_fcntl(*(int*)opaque, F_SETFD, 0);
}

static void* invalid_duplicator(void* opaque)
{
    int pin = *(int*)opaque;
    assert(user_exe_dup3(pin, pin, 0) == -EINVAL);
    assert(user_exe_dup3(-1, pin, ~O_CLOEXEC) == -EINVAL);
    return NULL;
}

static void* file_lock_waiter(void* opaque)
{
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    assert(!user_exe_fcntl(*(int*)opaque, F_OFD_SETLKW, (unsigned long)&lock));
    return NULL;
}

struct relocation { int source, target; };
static void* relocator(void* opaque)
{
    struct relocation* fds = opaque;
    atomic_store(&started, 1);
    assert(user_exe_dup3(fds->source, fds->target, 0) == fds->target);
    return NULL;
}

static void test_waiting_file_lock(void)
{
    char path[] = "/tmp/rvvm-fd-lock.XXXXXX";
    int holder = mkstemp(path), waiter = open(path, O_RDWR);
    assert(holder >= 0 && waiter >= 0 && !unlink(path));
    int source = open("/dev/null", O_RDONLY);
    pin_value = fcntl(source, F_DUPFD_CLOEXEC, 64);
    assert(source >= 0 && pin_value >= 64);
    struct relocation fds = {source, pin_value};
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    assert(!fcntl(holder, F_OFD_SETLK, &lock));
    pthread_t blocked, moving;
    assert(!pthread_create(&blocked, NULL, file_lock_waiter, &waiter));
    while (!atomic_load(&lock_waiting)) sched_yield();
    atomic_store(&started, 0);
    assert(!pthread_create(&moving, NULL, relocator, &fds));
    while (!atomic_load(&started)) sched_yield();
    struct timespec pause = {.tv_nsec = 50000000};
    nanosleep(&pause, NULL);
    // A queued relocation must not prevent the operation that releases
    // the native lock from progressing. The runner bounds a deadlock by timeout.
    lock.l_type = F_UNLCK;
    assert(!user_exe_fcntl(holder, F_OFD_SETLK, (unsigned long)&lock));
    assert(!pthread_join(blocked, NULL) && !pthread_join(moving, NULL));
    assert(!close(holder) && !close(waiter) && !close(source));
    assert(!close(fds.target) && !close(pin_value));
}

int main(void)
{
    int source = open("/dev/null", O_RDONLY), hole = open("/dev/null", O_RDONLY);
    assert(source >= 0 && hole >= 0);
    pin_value = fcntl(source, F_DUPFD_CLOEXEC, 64);
    assert(pin_value >= 64 && !close(hole));
    int original = pin_value;
    user_fd_lock();
    pthread_t invalid;
    assert(!pthread_create(&invalid, NULL, invalid_duplicator, &original));
    assert(!pthread_join(invalid, NULL)); // Argument errors cannot wait for the guard.
    user_fd_unlock();
    assert(user_exe_dup3(hole, original, 0) == -EBADF);
    assert(pin_value == original && fcntl(original, F_GETFD) == FD_CLOEXEC);

    // fcntl must classify after a concurrent relocation, then preserve CLOEXEC.
    user_fd_lock();
    pthread_t setter;
    atomic_store(&started, 0);
    assert(!pthread_create(&setter, NULL, flag_setter, &hole));
    while (!atomic_load(&started)) sched_yield();
    assert(user_exe_dup3(source, original, 0) == original);
    assert(pin_value == hole);
    user_fd_unlock();
    void* flags_result;
    assert(!pthread_join(setter, &flags_result));
    assert((long)flags_result == -EBADF && fcntl(hole, F_GETFD) == FD_CLOEXEC);
    assert(user_exe_fcntl(hole, F_GETFL, 0) == -EBADF);
    assert(user_exe_fcntl(hole, F_SETFL, 0) == -EBADF);
    assert(user_exe_dup(hole) == -EBADF);
    assert(user_exe_fcntl(source, F_GETFD, 0) == 0);
    int duplicate = user_exe_dup(source);
    assert(duplicate >= 0 && !close(duplicate));
    assert(!close(hole));
    pin_value = fcntl(source, F_DUPFD_CLOEXEC, 64);
    assert(pin_value >= 64);
    assert(!close(original));
    original = pin_value;

    // Hold relocation's lock while close starts, then move the pin into its fd.
    paused_fd = hole;
    pthread_mutex_lock(&user_exe_lock);
    pthread_t worker;
    assert(!pthread_create(&worker, NULL, closer, &hole));
    while (!atomic_load(&started)) sched_yield();
    struct timespec deadline;
    assert(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_nsec += 50000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
    pthread_mutex_lock(&pause_lock);
    while (!closing && pthread_cond_timedwait(&pause_cond, &pause_lock, &deadline) != ETIMEDOUT) {}
    int moved = fcntl(original, F_DUPFD_CLOEXEC, 0);
    assert(moved == hole && syscall(SYS_dup3, source, original, 0) == original);
    atomic_store(&pin_value, moved);
    released = 1;
    pthread_cond_broadcast(&pause_cond);
    pthread_mutex_unlock(&pause_lock);
    pthread_mutex_unlock(&user_exe_lock);
    void* result;
    assert(!pthread_join(worker, &result));
    assert((long)result == -EBADF && fcntl(moved, F_GETFD) == FD_CLOEXEC);
    paused_fd = -1;
    assert(!close(moved) && !close(original) && !close(source));
    test_waiting_file_lock();
    puts("PASS closed dup3 source, concurrent pin close/fcntl and private dup");
}
