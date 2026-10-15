/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A shared-mm VFORK child may create private-mm children with the flags an
 * ordinary fork accepts: CLONE_FILES shares the descriptor table both ways,
 * and CLONE_NEWUSER/NEWNS/NEWPID enter new namespaces. Each case runs from
 * the ordinary parent and from inside a shared-mm VFORK child, for fork-like
 * and private VFORK children. Namespace cases skip without unprivileged
 * user namespaces. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char stacks[3][256 * 1024];
static volatile int result;
static ino_t parent_user_ns;

static ino_t user_ns(void)
{
    struct stat st;
    return stat("/proc/self/ns/user", &st) ? 0 : st.st_ino;
}

static int status_of(pid_t pid)
{
    int status;
    if (pid < 0) return errno == EPERM || errno == EINVAL || errno == ENOSPC ? 77 : 100 + errno;
    if (waitpid(pid, &status, __WALL) != pid) return 99;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

/* Opens a descriptor and closes the one it was given: with CLONE_FILES the
 * caller sees both changes, without it neither. */
static int files_child(void* arg)
{
    int given = (int)(long)arg;
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || close(given)) _exit(2);
    _exit(fd > 0 && fd < 256 ? fd : 3);
}

static int userns_child(void* unused)
{
    (void)unused;
    ino_t ns = user_ns();
    _exit(ns && ns != parent_user_ns ? 0 : 4);
}

static int pidns_child(void* unused)
{
    (void)unused;
    _exit(getpid() == 1 ? 0 : 5);
}

static int files_case(unsigned extra)
{
    int given = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (given < 0) return 10;
    pid_t pid = clone(files_child, stacks[1] + sizeof(stacks[1]), CLONE_FILES | extra | SIGCHLD,
                      (void*)(long)given);
    if (pid < 0) return 14;
    int fd = status_of(pid);
    if (fd < 4 || fd >= 128) return 11;
    /* The child's open is ours to close, and its close removed ours. */
    if (fcntl(fd, F_GETFD) < 0 || close(fd)) return 12;
    if (fcntl(given, F_GETFD) >= 0 || errno != EBADF) return 13;
    return 0;
}

static int namespace_case(unsigned extra)
{
    pid_t pid = clone(userns_child, stacks[1] + sizeof(stacks[1]),
                      CLONE_NEWUSER | CLONE_NEWNS | extra | SIGCHLD, NULL);
    int status = status_of(pid);
    if (status) return status == 77 ? 77 : 20 + status;
    pid = clone(pidns_child, stacks[1] + sizeof(stacks[1]), CLONE_NEWUSER | CLONE_NEWPID | extra | SIGCHLD, NULL);
    status = status_of(pid);
    return status ? (status == 77 ? 77 : 30 + status) : 0;
}

static int run_cases(void)
{
    int files = files_case(0);
    if (files) return files;
    files = files_case(CLONE_VFORK);
    if (files) return 40 + files;
    int ns = namespace_case(0);
    if (ns && ns != 77) return ns;
    int nsv = namespace_case(CLONE_VFORK);
    if (nsv && nsv != 77) return 50 + nsv;
    return ns == 77 || nsv == 77 ? 77 : 0;
}

static int shared_child(void* unused)
{
    (void)unused;
    result = run_cases();
    _exit(0);
}

int main(void)
{
    alarm(30);
    parent_user_ns = user_ns();
    int direct = run_cases();
    if (direct && direct != 77) { printf("FAIL ordinary parent: %d\n", direct); return 1; }
    result = -1;
    pid_t pid = clone(shared_child, stacks[0] + sizeof(stacks[0]), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    if (status_of(pid) || (result && result != 77)) {
        printf("FAIL shared-mm VFORK child: %d\n", result);
        return 1;
    }
    printf("PASS CLONE_FILES and namespace forks from parent and shared-mm child%s\n",
           direct == 77 || result == 77 ? " (namespaces skipped)" : "");
    return 0;
}
