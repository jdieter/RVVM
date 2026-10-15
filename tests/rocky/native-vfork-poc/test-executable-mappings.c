/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static unsigned char* code;
static size_t page;
static atomic_int ready, changed;
static int mode;
static int churn;

static void write_code(void* address)
{
#if defined(__riscv)
    const uint32_t instructions[] = {0x02a00513, 0x00008067};
#elif defined(__x86_64__)
    const unsigned char instructions[] = {0xb8, 42, 0, 0, 0, 0xc3};
#elif defined(__aarch64__)
    const uint32_t instructions[] = {0x52800540, 0xd65f03c0};
#else
#error Unsupported native test architecture
#endif
    memcpy(address, instructions, sizeof(instructions));
#if defined(__riscv)
    assert(!syscall(SYS_riscv_flush_icache, address, (char*)address + sizeof(instructions), 0));
#endif
    __builtin___clear_cache(address, (char*)address + sizeof(instructions));
}

static int child(void* unused)
{
    (void)unused;
    if (!mode) {
        unsigned char* own = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (own == MAP_FAILED) _exit(101);
        write_code(own);
        if (mprotect(own, page * 2, PROT_READ | PROT_EXEC)) _exit(102);
        if (((int (*)(void))own)() != 42) _exit(103);
        own = mremap(own, page * 2, page * 4, MREMAP_MAYMOVE);
        if (own == MAP_FAILED || ((int (*)(void))own)() != 42) _exit(104);
        if (munmap(own, page * 4)) _exit(105);
    } else {
        atomic_store(&ready, 1);
        while (!atomic_load(&changed)) sched_yield();
        if (((int (*)(void))code)() != 42) _exit(106);
    }
    _exit(0);
}

static void* peer(void* unused)
{
    (void)unused;
    while (!atomic_load(&ready)) sched_yield();
    if (mode == 1 && churn) {
        for (int i = 0; i < 100000; ++i) {
            assert(!mprotect(code, page, PROT_READ | PROT_EXEC));
            assert(!mprotect(code, page, PROT_READ));
        }
    }
    assert(!mprotect(code, page, PROT_READ | (mode == 1 ? PROT_EXEC : 0)));
    atomic_store(&changed, 1);
    return NULL;
}

int main(int argc, char** argv)
{
    churn = argc == 2 && !strcmp(argv[1], "--churn");
    assert(argc == 1 || churn);
    alarm(20);
    page = sysconf(_SC_PAGESIZE);
    code = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(code != MAP_FAILED);
    write_code(code);
    if (churn) {
        unsigned long pages;
        FILE* statm = fopen("/proc/self/statm", "r");
        assert(statm && fscanf(statm, "%lu", &pages) == 1);
        fclose(statm);
        struct rlimit limit;
        assert(!getrlimit(RLIMIT_AS, &limit));
        limit.rlim_cur = pages * page + 32 * 1024 * 1024;
        assert(limit.rlim_cur <= limit.rlim_max && !setrlimit(RLIMIT_AS, &limit));
    }
    for (mode = 0; mode < 3; ++mode) {
        atomic_store(&ready, 0);
        atomic_store(&changed, 0);
        pthread_t controller;
        if (mode) assert(!pthread_create(&controller, NULL, peer, NULL));
        pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        int status;
        assert(pid > 0 && waitpid(pid, &status, 0) == pid);
        if (mode == 2) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
        else assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (mode) assert(!pthread_join(controller, NULL));
    }
    assert(!munmap(code, page));
    puts("PASS child executable mmap/mprotect/remap and live parent execute grants/revocations");
}
