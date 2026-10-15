/* SPDX-License-Identifier: GPL-3.0-or-later */
/* RVVM makes these children with a raw clone of one host thread, which runs
 * no libc recovery: CLONE_FILES and exit-signal 0/custom forks, private-mm
 * VFORK, and fork-like clones from a shared-mm VFORK child. Make them while
 * other guest threads are being created and joined (host pthread_create,
 * joins and RVVM allocation in flight), and require each child to create
 * and reap a thread of its own: a child that inherited a held host libc or
 * allocator lock hangs, and the alarm fails the test. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <unistd.h>

#define ROUNDS 60

static char stacks[2][256 * 1024];
static atomic_bool stop;
static volatile int nested_result;

static void exit_signal(int signal)
{
    (void)signal;
}

static void* nothing(void* arg)
{
    return arg;
}

static void* churn(void* unused)
{
    (void)unused;
    while (!atomic_load(&stop)) {
        pthread_t threads[4];
        for (int i = 0; i < 4; ++i)
            if (pthread_create(&threads[i], NULL, nothing, NULL)) return (void*)1;
        for (int i = 0; i < 4; ++i) pthread_join(threads[i], NULL);
        free(malloc(1 + rand() % 100000));
    }
    return NULL;
}

/* Runs in every child: a guest thread is a host thread, so this needs
 * RVVM's thread lifecycle and allocator. The guest side must stay off its
 * own libc locks, which the churn threads may hold: create the thread with
 * the raw clone wrapper, have it exit by syscall, and wait on its TID. */
static char thread_stack[64 * 1024];
static volatile pid_t thread_tid;

static int raw_thread(void* unused)
{
    (void)unused;
    syscall(SYS_exit, 0);
    return 0;
}

static int child(void* code)
{
    const int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
        | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    pid_t tid = clone(raw_thread, thread_stack + sizeof(thread_stack), flags, NULL,
                      &thread_tid, NULL, &thread_tid);
    if (tid <= 0) _exit(90);
    for (pid_t seen; (seen = thread_tid);) syscall(SYS_futex, &thread_tid, FUTEX_WAIT, seen, NULL, NULL, 0);
    _exit((int)(long)code);
}

static int wait_child(pid_t pid, int options)
{
    int status;
    if (pid < 0) return 100 + errno;
    if (waitpid(pid, &status, options) != pid) return 98;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int clone_case(unsigned flags, int expect, int wait_options)
{
    pid_t pid = clone(child, stacks[1] + sizeof(stacks[1]), flags, (void*)(long)expect);
    int status = wait_child(pid, wait_options);
    return status == expect ? 0 : status ? status : 97;
}

/* A shared-mm VFORK child that clones fork-like and private-VFORK children. */
/* Selects cases by bit: 1 << index for the direct cases, 0x100 for the
 * shared-mm child and 0x200/0x400/0x800 for its fork-like, private VFORK
 * and CLONE_FILES children. 0x80 disables the churn threads. */
static unsigned long mask = ~0x80UL;

static int nested(void* unused)
{
    (void)unused;
    int result = 0;
    if (mask & 0x200) result = clone_case(SIGCHLD, 31, 0);
    if (!result && (mask & 0x400)) result = clone_case(CLONE_VFORK | SIGCHLD, 32, 0);
    if (!result && (mask & 0x800)) result = clone_case(CLONE_FILES | SIGCHLD, 33, 0);
    nested_result = result;
    _exit(0);
}

int main(int argc, char** argv)
{
    if (argc > 1) mask = strtoul(argv[1], NULL, 0);
    alarm(240);
    struct sigaction action = {.sa_handler = exit_signal, .sa_flags = SA_RESTART};
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR2, &action, NULL);
    pthread_t churners[3];
    int churning = mask & 0x80 ? 0 : 3;
    for (int i = 0; i < churning; ++i)
        if (pthread_create(&churners[i], NULL, churn, NULL)) { puts("FAIL churn thread"); return 1; }
    for (int round = 0; round < ROUNDS; ++round) {
        struct { const char* name; unsigned flags; int expect, options; } cases[] = {
            {"CLONE_FILES|SIGCHLD", CLONE_FILES | SIGCHLD, 11, 0},
            {"exit signal 0", 0, 12, __WCLONE},
            {"exit signal SIGUSR2", SIGUSR2, 13, __WCLONE},
            {"CLONE_FILES, exit signal 0", CLONE_FILES, 14, __WCLONE},
            {"private VFORK", CLONE_VFORK | SIGCHLD, 15, 0},
            {"ordinary fork", SIGCHLD, 16, 0},
            {"private VFORK with CLONE_FILES", CLONE_VFORK | CLONE_FILES | SIGCHLD, 17, 0},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
            if (!(mask & (1UL << i))) continue;
            int result = clone_case(cases[i].flags, cases[i].expect, cases[i].options);
            if (result) { printf("FAIL %s, round %d: %d\n", cases[i].name, round, result); return 1; }
        }
        if (!(mask & 0x100)) continue;
        nested_result = -1;
        pid_t pid = clone(nested, stacks[0] + sizeof(stacks[0]), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        int status = wait_child(pid, 0);
        if (status || nested_result) {
            printf("FAIL shared-mm VFORK child, round %d: %d/%d\n", round, status, nested_result);
            return 1;
        }
    }
    atomic_store(&stop, true);
    for (int i = 0; i < churning; ++i) {
        void* result;
        pthread_join(churners[i], &result);
        if (result) { puts("FAIL churn thread"); return 1; }
    }
    printf("PASS %d rounds of raw-clone children during thread churn\n", ROUNDS);
    return 0;
}
