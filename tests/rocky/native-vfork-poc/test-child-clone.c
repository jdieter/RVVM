/* SPDX-License-Identifier: GPL-3.0-or-later */
/* clone from a shared-mm VFORK child before exec: fork (COW isolation and a
 * full runtime in the grandchild), nested VFORK (shared writes), posix_spawn
 * and fork+exec. Thread creation succeeds natively; RVVM reports EAGAIN, a
 * documented gap, and the result line says which happened. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
static char child_stack[256 * 1024], grandchild_stack[256 * 1024], thread_stack[64 * 1024];
static volatile int shared_value, cow_value;
static atomic_int thread_ran;

struct results {
    int fork_status, cow_seen, vfork_status, vfork_value, spawn_status, exec_status;
    int thread_result, thread_errno, thread_ran;
};

static void* runtime_thread(void* opaque) { return opaque; }

static int grandchild_vfork(void* unused)
{
    (void)unused;
    shared_value = 42;
    _exit(3);
}

static int grandchild_thread(void* unused)
{
    (void)unused;
    atomic_store(&thread_ran, 1);
    syscall(SYS_exit, 0);
    return 0;
}

static int wait_status(pid_t pid)
{
    int status;
    if (pid <= 0 || waitpid(pid, &status, 0) != pid) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int child(void* opaque)
{
    struct results* out = opaque;
    /* fork: a private copy with a working runtime. */
    pid_t pid = fork();
    if (!pid) {
        cow_value = 99;
        char* text = malloc(64);
        pthread_t thread;
        int ok = text && snprintf(text, 64, "grandchild %d", 7) > 0
              && !pthread_create(&thread, NULL, runtime_thread, text) && !pthread_join(thread, NULL);
        _exit(ok ? 7 : 1);
    }
    out->fork_status = wait_status(pid);
    out->cow_seen = cow_value;
    /* Nested VFORK shares memory with this child and its parent. */
    pid = clone(grandchild_vfork, grandchild_stack + sizeof(grandchild_stack),
                CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    out->vfork_status = wait_status(pid);
    out->vfork_value = shared_value;
    /* posix_spawn is a nested VFORK followed by exec. */
    char* args[] = {"/bin/true", NULL};
    out->spawn_status = posix_spawn(&pid, "/bin/true", NULL, NULL, args, environ) ? -1 : wait_status(pid);
    pid = fork();
    if (!pid) {
        execve("/bin/true", args, environ);
        _exit(127);
    }
    out->exec_status = wait_status(pid);
    /* A thread of this child. */
    int tid = clone(grandchild_thread, thread_stack + sizeof(thread_stack),
                    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM,
                    NULL);
    out->thread_result = tid;
    out->thread_errno = tid < 0 ? errno : 0;
    if (tid > 0) for (int i = 0; i < 1000 && !atomic_load(&thread_ran); ++i) sched_yield();
    out->thread_ran = atomic_load(&thread_ran);
    _exit(0);
}

int main(void)
{
    alarm(30);
    struct results results = {0};
    pid_t pid = clone(child, child_stack + sizeof(child_stack), CLONE_VM | CLONE_VFORK | SIGCHLD, &results);
    assert(wait_status(pid) == 0);
    int failed = 0;
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL %s\n", #condition); failed = 1; } } while (0)
    CHECK(results.fork_status == 7);
    CHECK(results.cow_seen == 0 && cow_value == 0);
    CHECK(results.vfork_status == 3 && results.vfork_value == 42 && shared_value == 42);
    CHECK(results.spawn_status == 0);
    CHECK(results.exec_status == 0);
    CHECK((results.thread_result > 0 && results.thread_ran)
          || (results.thread_result < 0 && results.thread_errno == EAGAIN));
    /* The parent's runtime still works after its child's nested clones. */
    char* text = malloc(32);
    CHECK(text && snprintf(text, 32, "parent") == 6);
    free(text);
    if (failed) {
        fprintf(stderr, "fork=%d cow=%d vfork=%d/%d spawn=%d exec=%d thread=%d errno=%d ran=%d\n",
                results.fork_status, results.cow_seen, results.vfork_status, results.vfork_value,
                results.spawn_status, results.exec_status, results.thread_result,
                results.thread_errno, results.thread_ran);
        return 1;
    }
    printf("PASS fork/nested VFORK/posix_spawn/fork+exec from shared-mm VFORK child; thread %s\n",
           results.thread_result > 0 ? "created" : "EAGAIN (unsupported)");
    return 0;
}
