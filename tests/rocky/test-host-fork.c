/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Raw forks recover libc's thread identity and RVVM's locks, under allocator
 * and thread-lifecycle contention, with kernel wait classes, CLONE_FILES and
 * namespaces, including hosts whose seccomp policy disables clone3. Built
 * against the public libc API only, statically and dynamically. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "util/threading.h"
#include "core/rvvm_user_malloc.h"
#include "core/rvvm_user_fork.h"

static atomic_bool stop;
static int guest_tid = 123;
static struct { void* prev; struct robust_list_head head; } guest_robust;
static struct { struct robust_list node; unsigned futex; } guest_mutex;

static void* allocate(void* continuous)
{
    for (unsigned i = 0; continuous ? !atomic_load(&stop) : i < 4096; ++i) {
        void* data = malloc(i & 1 ? 65537 : 200);
        assert(data);
        *(volatile char*)data = 1;
        free(data);
    }
    return NULL;
}

static void* nothing(void* arg)
{
    return arg;
}

/* Thread creation and joins in flight while the main thread forks: the child
 * must not inherit libc's stack cache or TLS locks held. */
static void* lifecycle(void* unused)
{
    (void)unused;
    while (!atomic_load(&stop)) {
        rvvm_thread_t* thread = rvvm_thread_create(nothing, NULL);
        assert(thread);
        if (!rvvm_thread_try_join(thread)) rvvm_thread_join(thread);
    }
    return NULL;
}

static void check_fork(unsigned signal, uint64_t extra)
{
    bool shared = extra & CLONE_FILES;
    int fd = shared ? open("/dev/null", O_RDONLY) : -1;
    assert(!shared || fd >= 0);
    pid_t pid = user_host_fork(signal, extra);
    if (pid < 0 && (extra & CLONE_NEWUSER) && (errno == EPERM || errno == EINVAL || errno == ENOSPC)) return;
    assert(pid >= 0);
    if (!pid) {
        assert(guest_tid == 123 && guest_robust.head.list.next == &guest_mutex.node);
        if (signal != SIGCHLD || extra) {
            assert(*user_fork_native_tid == syscall(SYS_gettid));
            struct robust_list_head* registered;
            size_t length;
            assert(!syscall(SYS_get_robust_list, 0, &registered, &length));
            assert(registered == user_fork_native_robust && registered != &guest_robust.head);
        }
        if (extra & CLONE_NEWPID) assert(getpid() == 1 && syscall(SYS_gettid) == 1);
        /* A libc fork() child, made while other threads were creating
         * threads, must still be able to make a raw fork of its own. */
        if (signal == SIGCHLD && !extra) {
            int inner_status;
            pid_t inner = user_host_fork(0, 0);
            assert(inner >= 0);
            if (!inner) _exit(9);
            assert(waitpid(inner, &inner_status, __WCLONE) == inner);
            assert(WIFEXITED(inner_status) && WEXITSTATUS(inner_status) == 9);
        }
        rvvm_thread_t* thread = rvvm_thread_create(allocate, NULL);
        assert(thread);
        rvvm_thread_join(thread);
        pthread_t native;
        assert(!pthread_create(&native, NULL, allocate, NULL));
        assert(!pthread_join(native, NULL));
        pthread_mutexattr_t attr;
        pthread_mutex_t mutex;
        assert(!pthread_mutexattr_init(&attr));
        assert(!pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
        assert(!pthread_mutex_init(&mutex, &attr));
        assert(!pthread_mutex_lock(&mutex));
        assert(!pthread_mutex_unlock(&mutex));
        assert(!pthread_mutex_destroy(&mutex));
        assert(!pthread_mutexattr_destroy(&attr));
        /* libc's cached TID routes signals to this thread, not the parent's. */
        assert(!pthread_kill(pthread_self(), 0));
        if (shared) assert(!close(fd));
        _exit(7);
    }
    int status;
    if (signal != SIGCHLD) {
        errno = 0;
        assert(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
    }
    assert(waitpid(pid, &status, signal == SIGCHLD ? 0 : __WCLONE) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
    if (shared) assert(fcntl(fd, F_GETFD) < 0 && errno == EBADF);
    if (signal == SIGUSR1) {
        sigset_t set;
        siginfo_t info;
        sigemptyset(&set);
        sigaddset(&set, signal);
        assert(sigwaitinfo(&set, &info) == (int)signal && info.si_pid == pid);
    }
}

static void check_forks(void)
{
    for (unsigned i = 0; i < 16; ++i) check_fork(0, 0);
    check_fork(SIGUSR1, 0);
    check_fork(SIGCHLD, 0);
    check_fork(SIGCHLD, CLONE_FILES);
    check_fork(0, CLONE_FILES);
    check_fork(SIGCHLD, CLONE_NEWUSER | CLONE_NEWNS);
    check_fork(SIGCHLD, CLONE_NEWUSER | CLONE_NEWPID);
}

int main(void)
{
    user_host_fork_init();
    assert(user_host_fork_ready());
    guest_robust.prev = &guest_mutex.node;
    guest_robust.head.list.next = &guest_mutex.node;
    guest_robust.head.futex_offset = sizeof(guest_mutex.node);
    guest_mutex.node.next = &guest_robust.head.list;
    assert(syscall(SYS_set_tid_address, &guest_tid) > 0);
    assert(!syscall(SYS_set_robust_list, &guest_robust.head, sizeof(guest_robust.head)));
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    assert(!pthread_sigmask(SIG_BLOCK, &set, NULL));
    rvvm_thread_t* workers[6];
    for (unsigned i = 0; i < 4; ++i) assert((workers[i] = rvvm_thread_create(allocate, (void*)1)));
    for (unsigned i = 4; i < 6; ++i) assert((workers[i] = rvvm_thread_create(lifecycle, NULL)));
    for (unsigned round = 0; round < 8; ++round) check_forks();
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {sizeof(instructions) / sizeof(*instructions), instructions};
    assert(!prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL));
    assert(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter, 0UL, 0UL));
    for (unsigned round = 0; round < 4; ++round) check_forks();
    atomic_store(&stop, true);
    for (unsigned i = 0; i < 6; ++i) rvvm_thread_join(workers[i]);
    puts("PASS raw fork recovery, lifecycle exclusion, exit signals, CLONE_FILES, namespaces, clone3 fallback");
}
