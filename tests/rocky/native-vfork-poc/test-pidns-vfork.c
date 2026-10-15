/* SPDX-License-Identifier: GPL-3.0-or-later */
/* VFORK after unshare(CLONE_NEWPID) makes the child init of the new PID
 * namespace. Each scenario runs in its own process, since a namespace
 * accepts no new tasks once its init exits: shared-mm VFORK with mapping
 * changes, posix_spawn, mixed parent/child TID stores, private VFORK, and
 * repeated spawns while a long-lived init keeps the namespace alive. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
static char stack[256 * 1024];
static volatile int seen_pid, seen_child_tid;
static volatile char* mapped;
static int parent_tid, child_tid;

static int shared_child(void* unused)
{
    (void)unused;
    seen_pid = getpid();
    seen_child_tid = child_tid;
    char* p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) _exit(10);
    strcpy(p, "init mapping");
    mapped = p;
    _exit(7);
}

static int private_child(void* unused)
{
    (void)unused;
    _exit(getpid() == 1 ? 9 : 11);
}

static int status_of(pid_t pid)
{
    int status;
    if (pid <= 0) fprintf(stderr, "clone/spawn failed: %s\n", strerror(errno));
    if (pid <= 0 || waitpid(pid, &status, 0) != pid) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int scenario(int which)
{
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID)) return errno == EPERM || errno == EINVAL ? 77 : 2;
    pid_t pid;
    switch (which) {
        case 0:
            pid = clone(shared_child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
            if (status_of(pid) != 7 || seen_pid != 1) return 3;
            return mapped && !strcmp((const char*)mapped, "init mapping") ? 0 : 4;
        case 1: {
            char* args[] = {"/bin/true", NULL};
            if (posix_spawn(&pid, "/bin/true", NULL, NULL, args, environ)) return 5;
            return status_of(pid) == 0 ? 0 : 6;
        }
        case 2:
            child_tid = -1;
            pid = clone(shared_child, stack + sizeof(stack),
                        CLONE_VM | CLONE_VFORK | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID
                        | CLONE_CHILD_CLEARTID | SIGCHLD, NULL, &parent_tid, NULL, &child_tid);
            if (status_of(pid) != 7) return 7;
            /* The parent's store uses its numbering, the child's its own. */
            if (parent_tid != pid || seen_child_tid != 1 || child_tid != 0) return 8;
            return 0;
        case 3:
            pid = clone(private_child, stack + sizeof(stack), CLONE_VFORK | SIGCHLD, NULL);
            return status_of(pid) == 9 ? 0 : 12;
        default: {
            /* Linux allows no new threads here: later spawns reuse workers. */
            char* sleeper[] = {"/bin/sleep", "2", NULL};
            pid_t init;
            if (posix_spawn(&init, "/bin/sleep", NULL, NULL, sleeper, environ)) return 13;
            for (int i = 0; i < 6; ++i) {
                char* args[] = {"/bin/true", NULL};
                if (posix_spawn(&pid, "/bin/true", NULL, NULL, args, environ)) return 14;
                if (status_of(pid)) return 15;
            }
            kill(init, SIGKILL);
            return status_of(init) == 128 + SIGKILL ? 0 : 16;
        }
    }
}

int main(void)
{
    alarm(30);
    static const char* names[] = {"shared VFORK", "posix_spawn", "mixed TID", "private VFORK", "repeated spawns"};
    int failed = 0, skipped = 0;
    for (int which = 0; which < 5; ++which) {
        fflush(stdout);
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) _exit(scenario(which));
        int result = status_of(pid);
        if (result == 77) { printf("SKIP %s: no unprivileged PID namespace\n", names[which]); ++skipped; }
        else if (result) { printf("FAIL %s: %d\n", names[which], result); failed = 1; }
    }
    if (failed) return 1;
    printf("PASS VFORK into a new PID namespace: shared, posix_spawn, mixed TID, private, repeated%s\n",
           skipped ? " (some skipped)" : "");
    return 0;
}
