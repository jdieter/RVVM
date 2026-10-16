/* SPDX-License-Identifier: GPL-3.0-or-later */
/* At RLIMIT_NPROC, Linux fails VFORK, posix_spawn and fork with EAGAIN.
 * Programs retry on EAGAIN, so a task limit must never surface as ENOMEM,
 * whichever task RVVM fails to create first. Runs in a child so the limit
 * stays contained; skips when running as root, which the limit exempts. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
static char stack[64 * 1024];

static int child_fn(void* unused)
{
    (void)unused;
    _exit(0);
}

static int check(const char* what, int ok, int error)
{
    if (ok) return 0;
    if (error == EAGAIN) return 0;
    printf("FAIL %s at RLIMIT_NPROC: %s (expected EAGAIN or success)\n", what, strerror(error));
    return 1;
}

static int limited(void)
{
    struct rlimit one = {1, 1};
    if (setrlimit(RLIMIT_NPROC, &one)) return 10;
    int failed = 0;
    errno = 0;
    pid_t pid = clone(child_fn, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int error = errno;
    if (pid > 0) waitpid(pid, NULL, 0);
    failed |= check("CLONE_VM|CLONE_VFORK", pid > 0, error);
    errno = 0;
    pid = clone(child_fn, stack + sizeof(stack), CLONE_VFORK | SIGCHLD, NULL);
    error = errno;
    if (pid > 0) waitpid(pid, NULL, 0);
    failed |= check("private VFORK", pid > 0, error);
    char* args[] = {"/bin/true", NULL};
    error = posix_spawn(&pid, "/bin/true", NULL, NULL, args, environ);
    if (!error) waitpid(pid, NULL, 0);
    failed |= check("posix_spawn", !error, error);
    errno = 0;
    pid = fork();
    if (pid == 0) _exit(0);
    error = errno;
    if (pid > 0) waitpid(pid, NULL, 0);
    failed |= check("fork", pid > 0, error);
    return failed;
}

int main(void)
{
    alarm(60);
    if (geteuid() == 0) {
        puts("SKIP RLIMIT_NPROC does not apply to root");
        return 0;
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int result = limited();
        fflush(stdout);
        _exit(result);
    }
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) return 1;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        printf("FAIL limited child status 0x%x\n", status);
        return 1;
    }
    puts("PASS VFORK, posix_spawn and fork at RLIMIT_NPROC fail only with EAGAIN");
    return 0;
}
