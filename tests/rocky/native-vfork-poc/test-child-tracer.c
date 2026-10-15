/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
#define TARGETS 40
static int tracer(void* argument)
{
    pid_t* targets = argument;
    for (unsigned i = 0; i < TARGETS; ++i) {
        assert(!ptrace(PTRACE_SEIZE, targets[i], 0, 0));
        assert(!ptrace(PTRACE_INTERRUPT, targets[i], 0, 0));
        siginfo_t info;
        assert(!waitid(P_PID, targets[i], &info, WSTOPPED | WNOWAIT | __WALL));
        assert(info.si_pid == targets[i] && info.si_code == CLD_TRAPPED);
    }
    /* Retain more than 32 stop/event allocations before consuming any. */
    for (unsigned i = 0; i < TARGETS; ++i) {
        int status;
        assert(waitpid(targets[i], &status, __WALL) == targets[i] && WIFSTOPPED(status));
        siginfo_t stop;
        assert(!ptrace(PTRACE_GETSIGINFO, targets[i], 0, &stop));
        assert(stop.si_signo == SIGTRAP);
        assert(!ptrace(PTRACE_DETACH, targets[i], 0, 0));
    }
    _exit(0);
}

int main(void)
{
    alarm(20);
    int ready[2];
    assert(!pipe(ready));
    pid_t targets[TARGETS];
    for (unsigned i = 0; i < TARGETS; ++i) {
        targets[i] = fork();
        assert(targets[i] >= 0);
        if (!targets[i]) {
            assert(!prctl(PR_SET_PDEATHSIG, SIGKILL));
            assert(!prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY));
            assert(write(ready[1], "r", 1) == 1);
            for (;;) pause();
        }
    }
    char byte;
    for (unsigned i = 0; i < TARGETS; ++i) assert(read(ready[0], &byte, 1) == 1);
    close(ready[0]); close(ready[1]);
    pid_t child = clone(tracer, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD,
                        targets);
    int status;
    assert(child > 0 && waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    for (unsigned i = 0; i < TARGETS; ++i) {
        assert(!kill(targets[i], SIGKILL));
        assert(waitpid(targets[i], &status, 0) == targets[i] && WIFSIGNALED(status));
    }
    puts("PASS shared-mm child tracing and waitid/wait4 ownership");
}
