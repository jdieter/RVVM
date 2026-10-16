/* SPDX-License-Identifier: GPL-3.0-or-later */
/* VFORK children where the host refuses clone3, as Docker's and Podman's
 * default seccomp profiles do (ENOSYS), other sandboxes with EPERM, and
 * Linux before 5.3. Run it under tests/rocky/noclone3 (see its comment):
 *
 *     noclone3 rvvm_user ./test-no-clone3
 *     noclone3 --eperm rvvm_user ./test-no-clone3
 *
 * RVVM must then make these children with clone(2). Covered: vfork() and
 * posix_spawn (shared mm), private VFORK, every combination of CLONE_PIDFD,
 * CLONE_PARENT_SETTID, CLONE_CHILD_SETTID and CLONE_CHILD_CLEARTID for both,
 * and VFORK children from a shared-mm VFORK child. It also passes without
 * the wrapper; the PASS line says whether a seccomp filter was active. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif

extern char** environ;

static char stacks[2][256 * 1024];
static volatile int shared_word;
static volatile pid_t parent_word, child_word;
static volatile int nested_result;

static int status_of(pid_t pid)
{
    int status;
    if (waitpid(pid, &status, __WALL) != pid) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int write_child(void* unused)
{
    (void)unused;
    shared_word = 1;
    _exit(7);
}

/* A private child reports its own CHILD_SETTID word, which the parent
 * cannot see: 0 when it holds this TID or was not requested. */
static int settid_child(void* arg)
{
    int flags = (int)(long)arg;
    shared_word = 1;
    if ((flags & CLONE_CHILD_SETTID) && child_word != (pid_t)syscall(SYS_gettid)) _exit(9);
    _exit(0);
}

static int spawn_self(void)
{
    char* argv[] = {"test-no-clone3", "exit42", NULL};
    pid_t pid;
    int error = posix_spawn(&pid, "/proc/self/exe", NULL, NULL, argv, environ);
    if (error) return 100 + error;
    return status_of(pid) == 42 ? 0 : 99;
}

static int vfork_case(void)
{
    shared_word = 0;
    pid_t pid = vfork();
    if (!pid) {
        shared_word = 1;
        _exit(7);
    }
    if (pid < 0) return 100 + errno;
    if (status_of(pid) != 7) return 1;
    return shared_word == 1 ? 0 : 2;
}

static int private_case(void)
{
    shared_word = 0;
    pid_t pid = clone(write_child, stacks[1] + sizeof(stacks[1]), CLONE_VFORK | SIGCHLD, NULL);
    if (pid < 0) return 100 + errno;
    if (status_of(pid) != 7) return 1;
    return shared_word == 0 ? 0 : 2;
}

/* One clone with these TID and pidfd flags, shared-mm or private VFORK. */
static int tid_case(int flags, int stack)
{
    int pidfd = -1;
    parent_word = 0;
    child_word = 0x7fffffff;
    shared_word = 0;
    void* parent = flags & CLONE_PIDFD ? (void*)&pidfd : (void*)&parent_word;
    pid_t pid = clone(settid_child, stacks[stack] + sizeof(stacks[stack]), flags | CLONE_VFORK | SIGCHLD,
                      (void*)(long)flags, parent, NULL, &child_word);
    if ((flags & CLONE_PIDFD) && (flags & CLONE_PARENT_SETTID)) {
        if (pid >= 0) { status_of(pid); return 1; }
        return errno == EINVAL ? 0 : 100 + errno;
    }
    if (pid < 0) return 100 + errno;
    if ((flags & CLONE_PARENT_SETTID) && parent_word != pid) { status_of(pid); return 2; }
    if (flags & CLONE_PIDFD) {
        /* Live until reaped, then gone: the pidfd names this child. */
        if (pidfd < 0 || syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0)) { status_of(pid); return 3; }
    }
    int status = status_of(pid);
    if (status) return 10 + status;
    if (flags & CLONE_PIDFD) {
        if (!syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) || errno != ESRCH) return 4;
        close(pidfd);
    }
    if (flags & CLONE_VM) {
        if (shared_word != 1) return 5;
        /* CLEARTID clears the word at exit, after any SETTID. */
        pid_t expected = flags & CLONE_CHILD_CLEARTID ? 0 : flags & CLONE_CHILD_SETTID ? pid : 0x7fffffff;
        if (child_word != expected) return 6;
    } else if (shared_word || child_word != 0x7fffffff) return 7;
    return 0;
}

static int tid_cases(int stack, char* failed, size_t size)
{
    static const int parents[] = {0, CLONE_PARENT_SETTID, CLONE_PIDFD, CLONE_PIDFD | CLONE_PARENT_SETTID};
    static const int children[] = {0, CLONE_CHILD_SETTID, CLONE_CHILD_CLEARTID,
                                   CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID};
    for (int vm = 0; vm < 2; ++vm)
        for (size_t p = 0; p < sizeof(parents) / sizeof(*parents); ++p)
            for (size_t c = 0; c < sizeof(children) / sizeof(*children); ++c) {
                int flags = (vm ? CLONE_VM : 0) | parents[p] | children[c];
                int result = tid_case(flags, stack);
                if (result) {
                    snprintf(failed, size, "flags %#x: %d", flags, result);
                    return result;
                }
            }
    return 0;
}

static char nested_failure[128];

static int run_cases(int stack, char* failed, size_t size)
{
    int result;
    if ((result = vfork_case())) { snprintf(failed, size, "vfork: %d", result); return result; }
    if ((result = spawn_self())) { snprintf(failed, size, "posix_spawn: %d", result); return result; }
    if ((result = private_case())) { snprintf(failed, size, "private VFORK: %d", result); return result; }
    return tid_cases(stack, failed, size);
}

static int nested_child(void* unused)
{
    (void)unused;
    nested_result = run_cases(1, nested_failure, sizeof(nested_failure));
    _exit(0);
}

static const char* host_filter(void)
{
    /* RVVM's /proc/self/status is the host process's: a filter installed
     * by the wrapper shows as mode 2. */
    FILE* status = fopen("/proc/self/status", "r");
    char line[128];
    const char* result = "unknown";
    while (status && fgets(line, sizeof(line), status))
        if (!strncmp(line, "Seccomp:", 8)) result = strtol(line + 8, NULL, 10) == 2 ? "yes" : "no";
    if (status) fclose(status);
    return result;
}

int main(int argc, char** argv)
{
    if (argc > 1 && !strcmp(argv[1], "exit42")) return 42;
    alarm(60);
    char failed[128];
    if (run_cases(0, failed, sizeof(failed))) {
        printf("FAIL ordinary parent, %s\n", failed);
        return 1;
    }
    nested_result = -1;
    pid_t pid = clone(nested_child, stacks[0] + sizeof(stacks[0]), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    if (pid < 0) {
        printf("FAIL shared-mm VFORK parent: errno %d\n", errno);
        return 1;
    }
    if (status_of(pid) || nested_result) {
        printf("FAIL shared-mm VFORK child, %s (%d)\n", nested_failure, nested_result);
        return 1;
    }
    printf("PASS VFORK without clone3: vfork, posix_spawn, private, TID/pidfd flags, nested"
           " (host seccomp filter: %s)\n", host_filter());
    return 0;
}
