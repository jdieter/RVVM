/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Preserve libc recovery under allocator contention and kernel wait classes,
 * including hosts whose seccomp policy disables clone3. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "core/rvvm_user_fork.h"

static atomic_bool stop;
static int guest_tid = 123;
static struct { void* prev; struct robust_list_head head; } guest_robust;
static struct { struct robust_list node; unsigned futex; } guest_mutex;
static void* allocate(void* continuous)
{
    for (unsigned i = 0; continuous ? !atomic_load(&stop) : i < 4096; ++i) {
        void* data = malloc(65537);
        assert(data);
        *(volatile char*)data = 1;
        free(data);
    }
    return NULL;
}

static void check_fork(unsigned signal, bool shared)
{
    int fd = shared ? open("/dev/null", O_RDONLY) : -1;
    assert(!shared || fd >= 0);
    pid_t pid = user_host_fork_files(signal, shared);
    assert(pid >= 0);
    if (!pid) {
        assert(guest_tid == 123 && guest_robust.head.list.next == &guest_mutex.node);
        assert(*user_fork_native_tid == syscall(SYS_gettid));
        struct robust_list_head* registered;
        size_t length;
        assert(!syscall(SYS_get_robust_list, 0, &registered, &length));
        assert(registered == user_fork_native_robust && registered != &guest_robust.head);
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, allocate, NULL));
        assert(!pthread_join(thread, NULL));
        pthread_mutexattr_t attr;
        pthread_mutex_t mutex;
        assert(!pthread_mutexattr_init(&attr));
        assert(!pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
        assert(!pthread_mutex_init(&mutex, &attr));
        assert(!pthread_mutex_lock(&mutex));
        assert(!pthread_mutex_unlock(&mutex));
        assert(!pthread_mutex_destroy(&mutex));
        assert(!pthread_mutexattr_destroy(&attr));
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

int main(void)
{
    user_host_fork_init();
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
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; ++i)
        assert(!pthread_create(workers + i, NULL, allocate, (void*)1));
    for (unsigned i = 0; i < 16; ++i) check_fork(0, false);
    check_fork(SIGUSR1, false);
    check_fork(SIGCHLD, false);
    check_fork(SIGCHLD, true);
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {sizeof(instructions) / sizeof(*instructions), instructions};
    assert(!prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL));
    assert(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter, 0UL, 0UL));
    for (unsigned i = 0; i < 16; ++i) check_fork(0, false);
    check_fork(SIGUSR1, false);
    check_fork(SIGCHLD, false);
    check_fork(SIGCHLD, true);
    atomic_store(&stop, true);
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(workers[i], NULL));
    puts("PASS native fork cleanup, exit signals, wait classes and clone3 fallback");
}
