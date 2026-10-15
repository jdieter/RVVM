/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static atomic_int ready, finish;

static int vfork_child(void* unused)
{
    (void)unused;
    atomic_store(&ready, 1);
    while (!atomic_load(&finish)) sched_yield();
    _exit(0);
}

static void* caller(void* unused)
{
    (void)unused;
    pid_t pid = clone(vfork_child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && !status);
    return NULL;
}

int main(void)
{
    alarm(30);
    pthread_t worker;
    assert(!pthread_create(&worker, NULL, caller, NULL));
    while (!atomic_load(&ready)) sched_yield();
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        size_t page = sysconf(_SC_PAGESIZE);
        void* code = mmap(NULL, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(code != MAP_FAILED);
        unsigned long pages;
        FILE* statm = fopen("/proc/self/statm", "r");
        assert(statm && fscanf(statm, "%lu", &pages) == 1 && !fclose(statm));
        struct rlimit limit;
        assert(!getrlimit(RLIMIT_AS, &limit));
        limit.rlim_cur = pages * page + 32 * 1024 * 1024;
        assert(limit.rlim_cur <= limit.rlim_max && !setrlimit(RLIMIT_AS, &limit));
        /* A private-mm fork retains the mappings, but none of its parent's
         * native vfork readers. Churn must remain bounded in the new mm. */
        for (unsigned i = 0; i < 100000; ++i) {
            assert(!mprotect(code, page, PROT_READ | PROT_EXEC));
            assert(!mprotect(code, page, PROT_READ));
        }
        assert(!munmap(code, page));
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && !status);
    atomic_store(&finish, 1);
    assert(!pthread_join(worker, NULL));
    puts("PASS ordinary fork during live vfork, 200000 executable permission changes, parent reader survives");
}
