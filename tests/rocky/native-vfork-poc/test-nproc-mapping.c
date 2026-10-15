/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A shared-mm VFORK child at its RLIMIT_NPROC limit can still change its
 * mappings: Linux needs no further task for mmap, mprotect, madvise, brk or
 * munmap. Effects are visible to the parent through the shared mm. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[256 * 1024];
static volatile char* mapped;
static volatile int errors[5];

static int child(void* unused)
{
    (void)unused;
    struct rlimit one = {1, 1};
    if (setrlimit(RLIMIT_NPROC, &one)) _exit(10);
    size_t page = sysconf(_SC_PAGESIZE);
    char* p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    errors[0] = p == MAP_FAILED ? errno : 0;
    if (p == MAP_FAILED) _exit(11);
    strcpy(p, "child mapping");
    errors[1] = mprotect(p + page, page, PROT_READ) ? errno : 0;
    errors[2] = madvise(p + 2 * page, page, MADV_DONTNEED) ? errno : 0;
    void* end = (void*)syscall(SYS_brk, 0);
    errors[3] = (void*)syscall(SYS_brk, (char*)end + page) == (char*)end + page ? 0 : ENOMEM;
    errors[4] = munmap(p + 3 * page, page) ? errno : 0;
    mapped = p;
    _exit(0);
}

int main(void)
{
    alarm(20);
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid);
    for (int i = 0; i < 5; ++i)
        if (errors[i]) fprintf(stderr, "operation %d: errno %d\n", i, errors[i]);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    for (int i = 0; i < 5; ++i) assert(!errors[i]);
    assert(mapped && !strcmp((const char*)mapped, "child mapping"));
    puts("PASS shared-mm VFORK child maps, protects, discards and unmaps at RLIMIT_NPROC");
    return 0;
}
