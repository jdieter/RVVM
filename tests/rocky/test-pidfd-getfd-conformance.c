/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native oracles for eventual pidfd_getfd support; RVVM currently returns ENOSYS. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #x, errno); return 1; } } while (0)
#define SKIP(s) do { fprintf(stderr, "prerequisite: %s\n", s); return 77; } while (0)
static int namespace_setup(void)
{
    if (unshare(CLONE_NEWNS)) {
        if (errno == EPERM || errno == ENOSYS) return 77;
        return 1;
    }
    CHECK(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    return 0;
}
static int mounts_setup(void)
{
    int ret = namespace_setup();
    if (ret) return ret;
    CHECK(!mkdir("mnt", 0700)); CHECK(!mkdir("other", 0700));
    CHECK(!mount("none", "mnt", "tmpfs", 0, "size=1m"));
    return 0;
}
#define MOUNTS() do { int r = mounts_setup(); if (r == 77) SKIP("private mount namespace denied"); CHECK(!r); } while (0)
static int pidfd_getfd_self(void)
{
    int fd = open("file", O_CREAT | O_RDWR, 0600); CHECK(fd >= 0);
    CHECK(write(fd, "abcdef", 6) == 6 && lseek(fd, 2, SEEK_SET) == 2);
    int pidfd = syscall(SYS_pidfd_open, getpid(), 0); CHECK(pidfd >= 0);
    int copied = syscall(SYS_pidfd_getfd, pidfd, fd, 0);
    if (copied < 0 && (errno == ENOSYS || errno == EPERM)) SKIP("host pidfd_getfd denied/unavailable");
    CHECK(copied >= 0 && fcntl(copied, F_GETFD) == FD_CLOEXEC);
    char c; CHECK(read(copied, &c, 1) == 1 && c == 'c' && lseek(fd, 0, SEEK_CUR) == 3);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, pidfd, 1024, 0) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, pidfd, 64, 0) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, 1024, fd, 1) == -1 && errno == EINVAL);
    close(copied); close(pidfd); close(fd); return 0;
}
static int pidfd_getfd_child(void)
{
    int file = open("file", O_CREAT | O_RDWR, 0600); CHECK(file >= 0);
    CHECK(write(file, "abcdef", 6) == 6 && lseek(file, 1, SEEK_SET) == 1);
    int ready[2]; CHECK(!pipe(ready));
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) { close(ready[0]); if (write(ready[1], "x", 1) != 1) _exit(1); for (;;) pause(); }
    close(ready[1]); char c; CHECK(read(ready[0], &c, 1) == 1);
    int pidfd = syscall(SYS_pidfd_open, child, 0); CHECK(pidfd >= 0);
    int copied = syscall(SYS_pidfd_getfd, pidfd, file, 0);
    int saved = errno;
    if (copied < 0) {
        kill(child, SIGKILL); waitpid(child, NULL, 0); errno = saved;
        if (errno == EPERM || errno == ENOSYS) SKIP("host pidfd_getfd denied/unavailable");
        return 1;
    }
    CHECK(read(copied, &c, 1) == 1 && c == 'b' && lseek(file, 0, SEEK_CUR) == 2);
    errno = 0; long hidden = syscall(SYS_pidfd_getfd, pidfd, 1024, 0); saved = errno;
    errno = 0; long hidden64 = syscall(SYS_pidfd_getfd, pidfd, 64, 0); int saved64 = errno;
    kill(child, SIGKILL); CHECK(waitpid(child, NULL, 0) == child);
    close(copied); close(pidfd); close(file); close(ready[0]);
    CHECK(hidden == -1 && saved == EBADF);
    CHECK(hidden64 == -1 && saved64 == EBADF);
    return 0;
}
static int pidfd_getfd_no_proc(void)
{
    MOUNTS();
    int file = open("file", O_CREAT | O_RDWR, 0600); CHECK(file >= 0);
    int pidfd = syscall(SYS_pidfd_open, getpid(), 0); CHECK(pidfd >= 0);
    CHECK(!chroot("mnt") && !chdir("/"));
    int copied = syscall(SYS_pidfd_getfd, pidfd, file, 0); CHECK(copied >= 0);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, pidfd, 64, 0) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, pidfd, 1024, 0) == -1 && errno == EBADF);
    close(copied); close(pidfd); close(file); return 0;
}
static int pidfd_getfd_no_slots(void)
{
    int file = open("file", O_CREAT | O_RDWR, 0600); CHECK(file >= 0);
    int pidfd = syscall(SYS_pidfd_open, getpid(), 0); CHECK(pidfd >= 0);
    struct rlimit limit; CHECK(!getrlimit(RLIMIT_NOFILE, &limit));
    limit.rlim_cur = 0; CHECK(!setrlimit(RLIMIT_NOFILE, &limit));
    errno = 0; long ret = syscall(SYS_pidfd_getfd, pidfd, file, 0);
    if (ret < 0 && (errno == EPERM || errno == ENOSYS)) SKIP("host pidfd_getfd denied/unavailable");
    CHECK(ret == -1 && errno == EMFILE);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, pidfd, 64, 0) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_pidfd_getfd, pidfd, 1024, 0) == -1 && errno == EBADF);
    close(pidfd); close(file); return 0;
}
static struct { const char* name; int (*run)(void); } cases[] = {
    {"pidfd-getfd-self", pidfd_getfd_self}, {"pidfd-getfd-child", pidfd_getfd_child},
    {"pidfd-getfd-no-proc", pidfd_getfd_no_proc}, {"pidfd-getfd-no-slots", pidfd_getfd_no_slots},
};
int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) puts(cases[i].name);
        return 0;
    }
    if (argc == 2) for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i)
        if (!strcmp(argv[1], cases[i].name)) return cases[i].run();
    return 2;
}
