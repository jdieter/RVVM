/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "util/feature_test.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "util/atomics.h"
#include "util/rvtimer.h"
#include "util/vma_ops.h"

static void user_fd_lock(void) {}
static void user_fd_unlock(void) {}
static void user_private_signals_restore(void) {}
#include "core/rvvm_user_jit_memory.h"

static void lock_still_owned(const char* path)
{
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        int fd = open(path, O_RDWR);
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
        assert(fd >= 0 && fcntl(fd, F_SETLK, &lock) < 0 && (errno == EAGAIN || errno == EACCES));
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && status == 0);
}

int main(void)
{
    char path[] = "/tmp/rvvm-jit-probe.XXXXXX";
    int fd = mkstemp(path);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    assert(fd >= 0 && !fcntl(fd, F_SETLK, &lock));
    struct rlimit original, finite;
    assert(!getrlimit(RLIMIT_NOFILE, &original));
    finite = original;
    finite.rlim_cur = 64;
    assert(!setrlimit(RLIMIT_NOFILE, &finite));
    int filled[64], count = 0, copy;
    while ((copy = dup(fd)) >= 0) filled[count++] = copy;
    assert(errno == EMFILE && count > 0);
    uint64_t mask = UINT64_MAX, old;
    assert(!syscall(SYS_rt_sigprocmask, SIG_SETMASK, &mask, &old, 8));
    errno = EDOM;
    assert(user_jit_memory_probe() > 0 && errno == EDOM);
    assert(!syscall(SYS_rt_sigprocmask, SIG_SETMASK, &old, NULL, 8));
    for (int i = 0; i < count; ++i) assert(fcntl(filled[i], F_GETFD) >= 0);
    assert(dup(fd) < 0 && errno == EMFILE); // Probe didn't change guest slots.
    assert(!setrlimit(RLIMIT_NOFILE, &original));
    lock_still_owned(path);
    finite.rlim_cur = 0;
    assert(!setrlimit(RLIMIT_NOFILE, &finite));
    uint64_t size = 0;
    pthread_t helper;
    assert(!pthread_create(&helper, NULL, user_jit_probe_worker, &size));
    assert(!pthread_join(helper, NULL) && !size);
    assert(fcntl(fd, F_GETFD) >= 0);
    assert(!setrlimit(RLIMIT_NOFILE, &original));
    lock_still_owned(path);
    for (int i = 0; i < count; ++i) close(filled[i]);
    close(fd);
    unlink(path);
    puts("PASS JIT memory probe with full/zero fd limits and POSIX locks");
    return 0;
}
