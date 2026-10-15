/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest memory faults inside shared-mm VFORK children leave the host through
 * the native fault jump. On an x86 host with a CET shadow stack that jump
 * must also restore the shadow stack, which the child shares with its
 * suspended parent. Repeated caught faults, a nested child's faults, an
 * uncaught fault, and faults in the parent afterwards must all behave.
 * An argument sets the faults per round. A jump that leaks shadow-stack
 * entries survives the default but, with an 8 MiB stack limit sizing the
 * shadow stack, dies of SIGSEGV at 100000 (passes at 80000). */
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>

static int rounds = 500;

static char stack[2][256 * 1024];
static volatile char* page;
static sigjmp_buf resume;
static volatile int caught;

static void on_segv(int sig)
{
    (void)sig;
    ++caught;
    siglongjmp(resume, 1);
}

static int fault_rounds(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_segv;
    if (sigaction(SIGSEGV, &action, NULL)) return -1;
    int start = caught;
    for (int i = 0; i < rounds; ++i) {
        if (!sigsetjmp(resume, 1)) {
            page[i % 4096] = 1;
            return -2;
        }
    }
    return caught - start;
}

static int status_of(pid_t pid)
{
    int status;
    if (pid <= 0 || waitpid(pid, &status, __WALL) != pid) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int grandchild(void* unused)
{
    (void)unused;
    _exit(fault_rounds() == rounds ? 0 : 20);
}

static int child(void* unused)
{
    (void)unused;
    if (fault_rounds() != rounds) _exit(10);
    pid_t pid = clone(grandchild, stack[1] + sizeof(stack[1]), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int result = status_of(pid);
    if (result) _exit(result == 20 ? 20 : 11);
    /* Faults keep working after the nested child returned. */
    _exit(fault_rounds() == rounds ? 0 : 12);
}

static int uncaught(void* unused)
{
    (void)unused;
    signal(SIGSEGV, SIG_DFL);
    page[0] = 1;
    _exit(30);
}

int main(int argc, char** argv)
{
    if (argc > 1) rounds = atoi(argv[1]);
    alarm(argc > 1 ? 600 : 60);
    page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 1;
    for (int round = 0; round < 3; ++round) {
        pid_t pid = clone(child, stack[0] + sizeof(stack[0]), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        int result = status_of(pid);
        if (result) { printf("FAIL caught faults in shared-mm child: %d\n", result); return 1; }
        pid = clone(uncaught, stack[0] + sizeof(stack[0]), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        result = status_of(pid);
        if (result != 128 + SIGSEGV) { printf("FAIL uncaught fault in shared-mm child: %d\n", result); return 1; }
        result = fault_rounds();
        if (result != rounds) { printf("FAIL parent faults after children: %d\n", result); return 1; }
    }
    printf("PASS shared-mm child, nested child and parent faults (%d caught)\n", caught);
    return 0;
}
