/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static char directory[] = "/tmp/native-vfork-io-XXXXXX";
static int child(void* unused)
{
    (void)unused;
    int pipes[2], sockets[2];
    char byte;
    if (pipe2(pipes, O_CLOEXEC | O_NONBLOCK) || write(pipes[1], "p", 1) != 1) _exit(101);
    struct pollfd wait = {.fd = pipes[0], .events = POLLIN};
    struct timespec timeout = {.tv_sec = 1};
    if (ppoll(&wait, 1, &timeout, NULL) != 1 || read(pipes[0], &byte, 1) != 1 || byte != 'p') _exit(102);
    close(pipes[0]); close(pipes[1]);
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets)
        || send(sockets[0], "s", 1, 0) != 1 || recv(sockets[1], &byte, 1, 0) != 1 || byte != 's') _exit(103);
    close(sockets[0]); close(sockets[1]);
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 || mkdirat(fd, "sub", 0700) || symlinkat("sub", fd, "link")
        || renameat(fd, "link", fd, "renamed") || unlinkat(fd, "renamed", 0)
        || unlinkat(fd, "sub", AT_REMOVEDIR)) _exit(104);
    close(fd);
    _exit(0);
}
int main(void)
{
    alarm(20);
    assert(mkdtemp(directory));
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) fprintf(stderr, "child IO status=%d\n", status);
    assert(!rmdir(directory));
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    puts("PASS child pipe/ppoll, socketpair IO and directory operations");
}
