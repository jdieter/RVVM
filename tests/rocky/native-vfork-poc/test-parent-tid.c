/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct state {
    int parent_tid, child_tid, observed_tid, observed_parent_tid, pid;
    atomic_int ready, finish;
    unsigned flags;
    int fault, kill_child;
};
static char stack[128 * 1024];

static int child(void* argument)
{
    struct state* state = argument;
    state->pid = syscall(SYS_getpid);
    state->observed_tid = state->child_tid;
    state->observed_parent_tid = state->parent_tid;
    atomic_store(&state->ready, 1);
    while (!atomic_load(&state->finish)) syscall(SYS_sched_yield);
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}

static void* control(void* argument)
{
    struct state* state = argument;
    int pid = 0;
    /* With a valid buffer this discovers the real kernel publication even
     * when SIGSTOP wins the race with the first guest instruction. */
    while (!pid) {
        if (!state->fault) pid = __atomic_load_n(&state->parent_tid, __ATOMIC_ACQUIRE);
        else if (atomic_load(&state->ready)) pid = state->pid;
        sched_yield();
    }
    assert(pid > 0 && !kill(pid, SIGSTOP));
    int status;
    assert(waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status));
    /* A stopped child must not keep a parent's allocator or signal-action
     * snapshot locked. Both operations finish before we resume or kill it. */
    void* allocation = malloc(8192);
    assert(allocation);
    free(allocation);
    struct sigaction action = {.sa_handler = SIG_IGN};
    assert(!sigaction(SIGUSR1, &action, NULL));
    if (state->kill_child) assert(!kill(pid, SIGKILL));
    else {
        atomic_store(&state->finish, 1);
        assert(!kill(pid, SIGCONT));
    }
    return NULL;
}

int main(int argc, char** argv)
{
    assert(argc == 1 || (argc == 2 && (!strcmp(argv[1], "--parent-only")
        || !strcmp(argv[1], "--parent-only-nofile-zero"))));
    unsigned tid_modes = argc == 2 ? 1 : 4;
    alarm(30);
    size_t page = sysconf(_SC_PAGESIZE);
    struct state* state = mmap(NULL, page, PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    void* inaccessible = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(state != MAP_FAILED && inaccessible != MAP_FAILED);
    if (argc == 2 && !strcmp(argv[1], "--parent-only-nofile-zero")) {
        const struct rlimit zero = {0, 0};
        assert(!setrlimit(RLIMIT_NOFILE, &zero));
    }
    unsigned cases = 0;
    for (unsigned shared = 0; shared < 2; ++shared)
        for (unsigned tids = 0; tids < tid_modes; ++tids)
            for (int fault = 0; fault < 3; ++fault)
                for (int killed = 0; killed < 2; ++killed) {
                    *state = (struct state){.fault = fault, .kill_child = killed};
                    state->flags = CLONE_VFORK | CLONE_PARENT_SETTID | SIGCHLD
                        | (shared ? CLONE_VM : 0)
                        | (tids & 1 ? CLONE_CHILD_SETTID : 0)
                        | (tids & 2 ? CLONE_CHILD_CLEARTID : 0);
                    pthread_t controller;
                    assert(!pthread_create(&controller, NULL, control, state));
                    int* parent_tid = !fault ? &state->parent_tid : fault == 1 ? NULL : inaccessible;
                    pid_t pid = clone(child, stack + sizeof(stack), state->flags,
                                      state, parent_tid, NULL, &state->child_tid);
                    assert(pid > 0);
                    if (!fault) assert(state->parent_tid == pid);
                    int status;
                    assert(waitpid(pid, &status, 0) == pid);
                    assert(!pthread_join(controller, NULL));
                    if (killed) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
                    else {
                        assert(WIFEXITED(status) && !WEXITSTATUS(status));
                        assert(state->pid == pid);
                        assert(state->observed_tid == (tids & 1 ? pid : 0));
                        if (!fault) assert(state->observed_parent_tid == pid);
                    }
                    /* Linux only clears the exit TID when the mm still has
                     * another user. A shared VMA alone isn't CLONE_VM. */
                    if ((tids & 2) && shared) assert(!state->child_tid);
                    else if (tids & 1) assert(state->child_tid == pid);
                    ++cases;
                }
    assert(!munmap(state, page) && !munmap(inaccessible, page));
    printf("PASS %u parent-TID combinations: shared/private mm, %s, faulted buffers, STOP/CONT/KILL\n",
           cases, tid_modes == 4 ? "child stores/clear" : "parent store without child-TID flags");
}
