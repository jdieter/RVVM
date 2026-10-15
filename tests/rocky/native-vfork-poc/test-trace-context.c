/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "core/user_ptrace/user_ptrace_events.h"

static char stack[128 * 1024];
static void* retained[96];
static unsigned allocations;
static void* allocate(void* opaque, size_t size, void* release)
{
    (void)opaque;
    if (release) {
        for (unsigned i = 0; i < allocations; ++i) if (retained[i] == release) {
            free(release); retained[i] = NULL; return NULL;
        }
        assert(!"release of unowned tracing storage");
    }
    assert(allocations < 96);
    return retained[allocations++] = malloc(size);
}
static int child(void* context)
{
    user_ptrace_events_context_select(context);
    user_ptrace_events_normalize_lock();
    syscall(SYS_kill, syscall(SYS_getpid), SIGKILL);
    __builtin_unreachable();
}

int main(void)
{
    alarm(20);
    struct user_ptrace_stop parent = {.pid = getpid(), .stopped = true}, copy;
    assert(user_ptrace_events_set(&parent));
    void* original = user_ptrace_events_context_current();
    void* private = user_ptrace_events_context_new();
    assert(private);
    user_ptrace_events_context_allocator(private, allocate, NULL);
    user_ptrace_events_context_select(private);
    assert(!user_ptrace_events_get(parent.pid, &copy));
    struct user_ptrace_stop independent = {.pid = parent.pid + 1, .stopped = true};
    assert(user_ptrace_events_set(&independent));
    for (unsigned i = 1; i < 96; ++i) {
        independent.pid++;
        assert(user_ptrace_events_set(&independent));
    }
    assert(allocations == 96);
    user_ptrace_events_context_select(original);
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, private);
    user_ptrace_events_context_select(original);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    user_ptrace_events_normalize_lock();
    assert(user_ptrace_events_get(parent.pid, &copy) && copy.stopped);
    assert(!user_ptrace_events_get(independent.pid, &copy));
    user_ptrace_events_normalize_unlock();
    /* The worker retires outstanding storage before releasing its header,
     * including nodes left linked when the child was killed. */
    for (unsigned i = 0; i < allocations; ++i) free(retained[i]);
    user_ptrace_events_context_free(private);
    user_ptrace_events_remove(parent.pid);
    puts("PASS borrowed tracing registries stay private after child SIGKILL with a held lock");
}
