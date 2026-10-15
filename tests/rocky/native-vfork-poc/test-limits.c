/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int marker;
static int child(void* unused)
{
    (void)unused;
    marker = 77;
    _exit(0);
}
int main(void)
{
    alarm(10);
    void* stack = mmap(NULL, 65536, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    struct rlimit saved, limited;
    assert(!getrlimit(RLIMIT_AS, &saved));
    unsigned long pages;
    FILE* statm = fopen("/proc/self/statm", "r");
    assert(statm && fscanf(statm, "%lu", &pages) == 1);
    fclose(statm);
    limited = saved;
    limited.rlim_cur = pages * (unsigned long)sysconf(_SC_PAGESIZE) + 16 * 1024 * 1024;
    assert(limited.rlim_cur <= saved.rlim_max && !setrlimit(RLIMIT_AS, &limited));
    int pid = clone(child, (char*)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    assert(pid > 0 && marker == 77);
    int status;
    assert(waitpid(pid, &status, 0) == pid && !status);
    limited.rlim_cur = 1;
    assert(!setrlimit(RLIMIT_AS, &limited));
    marker = 0;
    pid = clone(child, (char*)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int error = errno;
    assert(!setrlimit(RLIMIT_AS, &saved));
    /* Native hardware needs no new CPU/stack allocation and may succeed.
     * The interpreter must report its preparation failure transactionally. */
    if (pid > 0) assert(waitpid(pid, &status, 0) == pid && !status);
    else assert(error == ENOMEM && marker == 0);
    munmap(stack, 65536);
    printf("PASS finite-AS shared writes and allocation rollback (result=%d errno=%d)\n", pid, error);
}
