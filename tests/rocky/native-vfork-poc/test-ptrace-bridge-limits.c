/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "core/user_ptrace/user_ptrace.h"

static atomic_int start;
static uint64_t auxv[] = {0, 0};
static void* state[96];

static void* prepare(void* argument)
{
    unsigned first = (uintptr_t)argument;
    while (!atomic_load(&start)) sched_yield();
    for (unsigned i = first; i < first + 24; ++i) {
        state[i] = user_ptrace_prepare(NULL, auxv, sizeof(auxv), 0);
        assert(state[i]);
        char byte;
        struct iovec local = {&byte, 1};
        struct iovec remote = {(char*)state[i] - sysconf(_SC_PAGESIZE), 1};
        errno = 0;
        assert(syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0) == -1 && errno == EFAULT);
    }
    return NULL;
}

int main(void)
{
    void* initial = user_ptrace_prepare(NULL, auxv, sizeof(auxv), 0);
    assert(initial);
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; ++i)
        assert(!pthread_create(&workers[i], NULL, prepare, (void*)(uintptr_t)(i * 24)));
    struct rlimit zero = {0, 0};
    assert(!setrlimit(RLIMIT_NOFILE, &zero));
    assert(!setrlimit(RLIMIT_FSIZE, &zero));
    /* Exceed the recycled pool's maximum without returning any bridges. */
    atomic_store(&start, 1);
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(workers[i], NULL));
    for (unsigned i = 0; i < 96; ++i)
        for (unsigned j = 0; j < i; ++j) assert(state[i] != state[j]);
    for (unsigned i = 0; i < 96; ++i) user_ptrace_cancel(state[i]);
    user_ptrace_cancel(initial);
    puts("PASS 96 concurrent distinct ptrace bridges, protected aliases, hard NOFILE/FSIZE zero");
}
