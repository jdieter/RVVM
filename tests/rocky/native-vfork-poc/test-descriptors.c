/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int child_error;
static int source, mode, target, closed;
static char stack[128 * 1024];

static int child(void* unused)
{
    (void)unused;
    if (mode == 0) {
        struct stat before, after;
        if (fstat(source, &before) || dup3(source, target, 0) != target
            || fstat(target, &after) || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino) goto fail;
        errno = 0;
        if (syscall(SYS_fcntl, (UINT64_C(1) << 32) | (unsigned)closed, F_GETFD, 0) != -1
            || errno != EBADF) goto fail;
    } else if (mode == 1) {
        if (syscall(SYS_close_range, 0U, ~0U, 0U)) goto fail;
    } else {
        struct open_how how = { .flags = O_PATH | O_DIRECTORY | O_CLOEXEC };
        int fd = syscall(SYS_openat2, AT_FDCWD, "/", &how, sizeof(how));
        if (fd < 0 || !(fcntl(fd, F_GETFL) & O_DIRECTORY)) goto fail;
        close(fd);
    }
    char* args[] = { "descriptor-probe", "--reexec", NULL };
    char* env[] = { NULL };
    execve("/proc/self/exe", args, env);
fail:
    child_error = errno ? errno : EIO;
    _exit(117);
}

int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--reexec")) return 33;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur <= 64) return 2;
    target = limit.rlim_cur > 1024 ? 1024 : 64;
    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (source < 0) return 2;
    closed = fcntl(source, F_DUPFD_CLOEXEC, 0);
    if (closed < 0 || close(closed)) return 2;
    for (mode = 0; mode < 3; ++mode) {
        child_error = 0;
        pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        int status = 0;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || status != 33 * 256 || child_error) {
            fprintf(stderr, "FAIL descriptors mode=%d status=%d errno=%d\n", mode, status, child_error);
            return 1;
        }
        if (fcntl(source, F_GETFD) != FD_CLOEXEC) return 1;
        printf("PASS descriptors mode=%d target=%d\n", mode, target);
    }
    close(source);
    return 0;
}
