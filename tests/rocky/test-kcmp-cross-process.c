/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#define SKIP(s) do { fprintf(stderr, "prerequisite: %s\n", s); return 77; } while (0)
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #x, errno); return 1; } } while (0)
static int kcmp_files(void)
{
    int fd = open("file", O_CREAT | O_RDWR, 0600); CHECK(fd >= 0);
    int other = dup(fd); CHECK(other >= 0);
    long ret = syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, fd, other);
    if (ret < 0 && (errno == ENOSYS || errno == EPERM)) { close(fd); close(other); SKIP("host kcmp denied/unavailable"); }
    CHECK(!ret);
    errno = 0; CHECK(syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, 64, 64) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, 1024, 1024) == -1 && errno == EBADF);
    CHECK(!syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0));
    close(fd); close(other); return 0;
}
static int kcmp_epoll(void)
{
    int pipefd[2]; CHECK(!pipe(pipefd));
    int fd = epoll_create1(EPOLL_CLOEXEC); CHECK(fd >= 0);
    struct epoll_event event = {.events = EPOLLIN}; CHECK(!epoll_ctl(fd, EPOLL_CTL_ADD, pipefd[0], &event));
    struct kcmp_epoll_slot slot = {.efd = fd, .tfd = pipefd[0]};
    long ret = syscall(SYS_kcmp, getpid(), getpid(), KCMP_EPOLL_TFD, pipefd[0], &slot);
    if (ret < 0 && (errno == ENOSYS || errno == EPERM)) SKIP("host kcmp denied/unavailable");
    CHECK(!ret);
    slot.efd = 1024; errno = 0;
    CHECK(syscall(SYS_kcmp, getpid(), getpid(), KCMP_EPOLL_TFD, pipefd[0], &slot) == -1 && errno == EBADF);
    errno = 0;
    CHECK(syscall(SYS_kcmp, getpid(), getpid(), KCMP_EPOLL_TFD, pipefd[0], (void*)1) == -1 && errno == EFAULT);
    close(fd); close(pipefd[0]); close(pipefd[1]); return 0;
}
static int remote_pins(void)
{
    int file = open("file", O_CREAT | O_RDWR, 0600); CHECK(file >= 0);
    int ready[2]; CHECK(!pipe(ready));
    CHECK(fcntl(64, F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(1024, F_GETFD) == -1 && errno == EBADF);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) { close(ready[0]); if (write(ready[1], "x", 1) != 1) _exit(1); for (;;) pause(); }
    close(ready[1]); char c; CHECK(read(ready[0], &c, 1) == 1);
    long control = syscall(SYS_kcmp, getpid(), child, KCMP_FILE, file, file);
    int saved = errno;
    errno = 0; long a = syscall(SYS_kcmp, getpid(), child, KCMP_FILE, file, 64); int ea = errno;
    errno = 0; long b = syscall(SYS_kcmp, getpid(), child, KCMP_FILE, file, 1024); int eb = errno;
    kill(child, SIGKILL); CHECK(waitpid(child, NULL, 0) == child);
    close(file); close(ready[0]);
    if (control < 0 && (saved == EPERM || saved == ENOSYS)) return 77;
    CHECK(!control);
    if (a != -1 || ea != EBADF || b != -1 || eb != EBADF) {
        fprintf(stderr, "closed target descriptors: 64=%ld/%d, 1024=%ld/%d; expected -1/EBADF\n", a, ea, b, eb);
        return 1;
    }
    return 0;
}
static int shared_vm_child(void* parent)
{
    long ret = syscall(SYS_kcmp, getpid(), (pid_t)(intptr_t)parent, KCMP_VM, 0, 0);
    if (ret < 0 && (errno == EPERM || errno == ENOSYS)) _exit(77);
    if (ret != 0) {
        fprintf(stderr, "CLONE_VM KCMP_VM returned %ld (errno=%d), expected 0\n", ret, errno);
        _exit(1);
    }
    _exit(0);
}
static int shared_vm(void)
{
    size_t size = 65536;
    void* stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED);
    pid_t child = clone(shared_vm_child, (char*)stack + size, CLONE_VM | CLONE_VFORK | SIGCHLD, (void*)(intptr_t)getpid());
    CHECK(child > 0);
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    munmap(stack, size);
    return WEXITSTATUS(status);
}
int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--list")) { puts("kcmp-files"); puts("kcmp-epoll"); puts("kcmp-remote-pins"); puts("kcmp-shared-vm"); return 0; }
    if (argc == 2 && !strcmp(argv[1], "kcmp-files")) return kcmp_files();
    if (argc == 2 && !strcmp(argv[1], "kcmp-epoll")) return kcmp_epoll();
    if (argc == 2 && !strcmp(argv[1], "kcmp-remote-pins")) return remote_pins();
    if (argc == 2 && !strcmp(argv[1], "kcmp-shared-vm")) return shared_vm();
    return 2;
}
