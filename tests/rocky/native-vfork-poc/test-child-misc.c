/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static char stack[128 * 1024];

static int child(void* unused)
{
    (void)unused;
    unsigned char random[32];
    struct utsname name;
    if (uname(&name) || strcmp(name.sysname, "Linux") || !*name.nodename) _exit(115);
#if defined(__riscv)
    if (strcmp(name.machine, "riscv64")) _exit(116);
#endif
    uid_t r, e, s;
    gid_t gr, ge, gs;
    if (syscall(SYS_getresuid, &r, &e, &s) || r != getuid() || e != geteuid()
        || syscall(SYS_getresgid, &gr, &ge, &gs) || gr != getgid() || ge != getegid()
        || syscall(SYS_setresuid, r, e, s) || syscall(SYS_setresgid, gr, ge, gs)) _exit(112);
    errno = 0;
    if (syscall(SYS_getresuid, NULL, &e, &s) != -1 || errno != EFAULT) _exit(113);
    errno = 0;
    if (syscall(SYS_getresgid, &gr, NULL, &gs) != -1 || errno != EFAULT) _exit(114);
    struct timespec time;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &time) || time.tv_nsec < 0
        || time.tv_nsec >= 1000000000 || syscall(SYS_clock_getres, CLOCK_MONOTONIC, &time)
        || syscall(SYS_clock_getres, CLOCK_MONOTONIC, NULL)) _exit(117);
    errno = 0;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, NULL) != -1 || errno != EFAULT) _exit(118);
    errno = 0;
    if (syscall(SYS_clock_getres, CLOCK_MONOTONIC, (void*)1) != -1 || errno != EFAULT) _exit(119);
    int pipefd[2];
    int pollfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0xfedcba9876543210ULL};
    if (pollfd < 0 || pipe2(pipefd, O_CLOEXEC)
        || epoll_ctl(pollfd, EPOLL_CTL_ADD, pipefd[0], &event)
        || write(pipefd[1], "x", 1) != 1) _exit(120);
    memset(&event, 0, sizeof(event));
    if (epoll_pwait(pollfd, &event, 1, 0, NULL) != 1 || !(event.events & EPOLLIN)
        || event.data.u64 != 0xfedcba9876543210ULL) _exit(121);
    errno = 0;
    if (syscall(SYS_epoll_ctl, pollfd, EPOLL_CTL_MOD, pipefd[0], (void*)1) != -1
        || errno != EFAULT) _exit(122);
    if (epoll_ctl(pollfd, EPOLL_CTL_DEL, pipefd[0], (void*)1)) _exit(123);
    close(pipefd[0]); close(pipefd[1]); close(pollfd);
    int notify = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    int watch = notify < 0 ? -1 : inotify_add_watch(notify, "/", IN_ATTRIB);
    if (watch < 0 || inotify_rm_watch(notify, watch)) _exit(124);
    close(notify);
    int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec disarmed = {0}, oldtimer;
    if (timerfd < 0 || timerfd_settime(timerfd, 0, &disarmed, &oldtimer)
        || timerfd_gettime(timerfd, &oldtimer) || oldtimer.it_value.tv_sec
        || oldtimer.it_value.tv_nsec) _exit(125);
    close(timerfd);
    int other[2]; char byte;
    if (pipe2(pipefd, O_CLOEXEC) || pipe2(other, O_CLOEXEC)
        || write(pipefd[1], "t", 1) != 1 || tee(pipefd[0], other[1], 1, 0) != 1
        || read(other[0], &byte, 1) != 1 || byte != 't'
        || splice(pipefd[0], NULL, other[1], NULL, 1, 0) != 1
        || read(other[0], &byte, 1) != 1 || byte != 't') _exit(126);
    close(pipefd[0]); close(pipefd[1]); close(other[0]); close(other[1]);
    struct { unsigned size, policy; unsigned long long flags;
        int nice; unsigned priority; unsigned long long runtime, deadline, period;
        unsigned util_min, util_max; } attribute = {.size = sizeof(attribute)};
    if (syscall(SYS_sched_getattr, 0, &attribute, sizeof(attribute), 0)
        || syscall(SYS_ioprio_get, 1, 0) < 0) _exit(127);
    errno = 0;
    if (syscall(SYS_vmsplice, -1, NULL, 1, 0) != -1 || errno != EBADF) _exit(128);
    errno = 0;
    if (syscall(SYS_recvmmsg, -1, NULL, 1, MSG_DONTWAIT, NULL) != -1 || errno != EBADF) _exit(129);
    errno = 0;
    if (syscall(SYS_semctl, -1, 0, GETVAL, 0) != -1 || errno != EINVAL) _exit(130);
    struct msqid_ds queue;
    errno = 0;
    if (syscall(SYS_msgctl, -1, IPC_STAT, &queue) != -1 || errno != EINVAL) _exit(131);
    if (syscall(SYS_getrandom, random, sizeof(random), GRND_NONBLOCK) != sizeof(random)) _exit(101);
    struct statx stat;
    if (syscall(SYS_statx, AT_FDCWD, "/", 0, STATX_TYPE, &stat)
        || !(stat.stx_mask & STATX_TYPE) || !S_ISDIR(stat.stx_mode)) _exit(102);
    errno = 0;
    if (syscall(SYS_statx, AT_FDCWD, "/", 0, STATX_TYPE, NULL) != -1 || errno != EFAULT) _exit(103);
    int fd = syscall(SYS_memfd_create, "child-misc", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, 8192) || fchmod(fd, 0600)
        || fchown(fd, getuid(), getgid()) || syscall(SYS_fallocate, fd, 0, 0, 4096)
        || syscall(SYS_fadvise64, fd, 0, 4096, POSIX_FADV_SEQUENTIAL)
        || syscall(SYS_readahead, fd, 0, 4096)) _exit(104);
    struct statfs fs;
    if (fstatfs(fd, &fs) || fs.f_bsize <= 0) _exit(105);
    if (fsetxattr(fd, "user.fixture", "value", 5, XATTR_CREATE)) _exit(106);
    char bytes[4096];
    if (fgetxattr(fd, "user.fixture", bytes, sizeof(bytes)) != 5 || memcmp(bytes, "value", 5)
        || flistxattr(fd, bytes, sizeof(bytes)) < 1 || fremovexattr(fd, "user.fixture")) _exit(107);
    close(fd);
    fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 || syscall(SYS_getdents64, fd, bytes, sizeof(bytes)) <= 0) _exit(108);
    close(fd);
    if (statfs("/", &fs) || fs.f_bsize <= 0) _exit(109);
    struct sysinfo info;
    struct itimerval timer = {0}, previous;
    if (sysinfo(&info) || !info.totalram || getitimer(ITIMER_REAL, &previous)
        || setitimer(ITIMER_REAL, &timer, &previous)) _exit(110);
    int pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0 || syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0)) _exit(111);
    close(pidfd);
    _exit(0);
}

int main(int argc, char** argv)
{
    int ordinary = argc == 2 && !strcmp(argv[1], "--ordinary");
    assert(argc == 1 || ordinary);
    alarm(20);
    pid_t pid = ordinary ? fork()
        : clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    if (!pid) child(NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid);
    if (status) fprintf(stderr, "child misc status=%d\n", status);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    puts("PASS child credentials/clocks/EFAULT, epoll/inotify/timerfd/splice, filesystem/timers/pidfd");
}
