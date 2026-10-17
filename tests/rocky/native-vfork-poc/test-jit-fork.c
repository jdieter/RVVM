/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A fork child must not share its parent's JIT code cache. Where the host
 * refuses writable-executable memory (prctl MDWE, SELinux execmem), RVVM
 * keeps generated code in one memfd mapped twice, writable and executable.
 * Those mappings are shared, so a child that kept them would compile into
 * the same pages as its parent, and each would run the other's code.
 *
 * Each round, a parent and its child both flush the JIT (riscv_flush_icache)
 * and run families of distinct functions, so both compile fresh code at the
 * same cache offsets at the same time, then run it again and again. Every
 * result is checked against a table computed before the first fork. Cases:
 * ordinary fork, a CLONE_FILES fork (RVVM's raw clone), a private VFORK and
 * a shared-mm VFORK. While a VFORK child runs, a parent thread keeps
 * compiling. Run it under mdwe-exec to get the shared-cache layout. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROUNDS 20
#define FUNCS 96
#define FAMILIES 3

#define F(k) \
    static __attribute__((noinline)) uint64_t f##k(uint64_t x) \
    { \
        for (int i = 0; i < 12 + (k) % 5; ++i) { \
            x = x * (UINT64_C(0x9e3779b97f4a7c15) + 2 * (k)) + UINT64_C(0x1234567) * ((k) + 1); \
            x ^= x >> ((k) % 29 + 3); \
            if (x & ((k) + 1)) x += (k) * 77; \
        } \
        return x; \
    }
#define F8(b) F(b##0) F(b##1) F(b##2) F(b##3) F(b##4) F(b##5) F(b##6) F(b##7)
#define L8(b) f##b##0, f##b##1, f##b##2, f##b##3, f##b##4, f##b##5, f##b##6, f##b##7
F(0) F(1) F(2) F(3) F(4) F(5) F(6) F(7)
F8(1) F8(2) F8(3) F8(4) F8(5) F8(6) F8(7) F8(8) F8(9) F8(10) F8(11)

static uint64_t (*const funcs[FUNCS])(uint64_t) = {
    f0, f1, f2, f3, f4, f5, f6, f7,
    L8(1), L8(2), L8(3), L8(4), L8(5), L8(6), L8(7), L8(8), L8(9), L8(10), L8(11),
};
static uint64_t inputs[FUNCS], expected[FUNCS];
static char stacks[2][256 * 1024];
static atomic_bool stop;
static atomic_int worker_failed;

/* Drop every compiled block, as a guest JIT does after writing code. */
static void flush_jit(void)
{
    syscall(259, (long)funcs[0], (long)funcs[0] + 1, 0); // riscv_flush_icache
}

/* Runs family's functions, flushing now and then; 0 on success. */
static int run_family(int family, int iterations)
{
    for (int it = 0; it < iterations; ++it) {
        if (it % 16 == 0) flush_jit();
        for (int k = family; k < FUNCS; k += FAMILIES)
            if (funcs[k](inputs[k]) != expected[k]) return 1;
    }
    return 0;
}

/* Keeps another parent thread compiling while a VFORK child runs. */
static void* worker(void* unused)
{
    (void)unused;
    while (!atomic_load(&stop))
        if (run_family(2, 4)) { atomic_store(&worker_failed, 1); break; }
    return NULL;
}

static int child(void* iterations)
{
    _exit(run_family(1, (int)(long)iterations));
}

static int wait_child(pid_t pid)
{
    int status;
    if (pid < 0) return 100 + errno;
    if (waitpid(pid, &status, 0) != pid) return 98;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

int main(void)
{
    alarm(240);
    for (int k = 0; k < FUNCS; ++k) {
        inputs[k] = UINT64_C(0x0123456789abcdef) * (k + 3) ^ (uint64_t)getpid() << 7;
        expected[k] = funcs[k](inputs[k]);
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) { puts("FAIL worker thread"); return 1; }
    for (int round = 0; round < ROUNDS; ++round) {
        struct { const char* name; unsigned flags; bool fork; long iterations; } cases[] = {
            {"ordinary fork", 0, true, 400},
            {"CLONE_FILES fork", CLONE_FILES | SIGCHLD, false, 400},
            {"private VFORK", CLONE_VFORK | SIGCHLD, false, 40},
            {"shared-mm VFORK", CLONE_VM | CLONE_VFORK | SIGCHLD, false, 40},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
            pid_t pid;
            if (cases[i].fork) {
                pid = fork();
                if (!pid) child((void*)cases[i].iterations);
            } else {
                pid = clone(child, stacks[i & 1] + sizeof(stacks[0]), cases[i].flags,
                            (void*)cases[i].iterations);
            }
            int parent = run_family(0, 400);
            int status = wait_child(pid);
            if (parent || status || atomic_load(&worker_failed)) {
                printf("FAIL %s, round %d: parent %d, child %d, worker %d\n", cases[i].name,
                       round, parent, status, atomic_load(&worker_failed));
                return 1;
            }
        }
    }
    atomic_store(&stop, true);
    pthread_join(thread, NULL);
    if (atomic_load(&worker_failed)) { puts("FAIL worker thread results"); return 1; }
    printf("PASS %d rounds of JIT work across fork and VFORK children\n", ROUNDS);
    return 0;
}
