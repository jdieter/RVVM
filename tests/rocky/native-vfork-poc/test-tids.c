/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/sched.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct state { int tid, observed, pid, ppid; };
static int child(void* argument)
{
    struct state* state = argument;
    state->observed = state->tid;
    state->pid = getpid();
    state->ppid = getppid();
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}
int main(void)
{
    alarm(10);
    size_t size = 1024 * 1024;
    void* stack = mmap(NULL, size, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    struct state state = {0};
    int published = 0;
    int pid = clone(child, (char*)stack + size,
                    CLONE_VM | CLONE_VFORK | CLONE_PARENT_SETTID
                    | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD,
                    &state, &published, NULL, &state.tid);
    assert(pid > 0 && pid == published && pid == state.pid && pid == state.observed);
    assert(state.ppid == getpid());
    int status;
    assert(waitpid(pid, &status, 0) == pid && status == 0 && state.tid == 0);
    int pidfd = -1;
    state = (struct state){0};
    pid = clone(child, (char*)stack + size, CLONE_VM | CLONE_VFORK | CLONE_PIDFD | SIGCHLD,
                &state, &pidfd, NULL, NULL);
    assert(pid > 0 && pid == state.pid && pidfd >= 0);
    struct pollfd fd = {.fd = pidfd, .events = POLLIN};
    assert(poll(&fd, 1, 1000) == 1 && (fd.revents & POLLIN));
    assert(waitpid(pid, &status, 0) == pid && status == 0);
    close(pidfd);
    munmap(stack, size);
    puts("PASS real child PID/PPID, parent/child TID, clear-tid, pidfd");
}
