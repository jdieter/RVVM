/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static const char* executable;
static int prefix;
static void paths(void)
{
    if (!prefix) return;
    char buffer[256];
    assert(getcwd(buffer, sizeof(buffer)) && !strcmp(buffer, "/"));
    int fd = open("/etc/rvvm-prefix-poc", O_RDONLY);
    assert(fd >= 0 && read(fd, buffer, 7) == 7 && !memcmp(buffer, "prefix\n", 7));
    assert(!close(fd));
    ssize_t n = readlink("/etc/rvvm-prefix-link", buffer, sizeof(buffer));
    assert(n == 20 && !memcmp(buffer, "/etc/rvvm-prefix-poc", 20));
    n = readlink("/proc/self/exe", buffer, sizeof(buffer));
    assert(n == (ssize_t)strlen(executable) && !memcmp(buffer, executable, n));
}
static int child(void* execute)
{
    assert(!getuid() && !getgid());
    paths();
    if (execute) {
        char* args[] = {(char*)executable, "--after-exec", NULL};
        execv(executable, args);
        _exit(99);
    }
    /* Fake root must belong to the child even when the native mm is shared. */
    assert(!setuid(1234) && !setgid(1235));
    assert(getuid() == 1234 && getgid() == 1235);
    _exit(0);
}
int main(int argc, char** argv)
{
    alarm(10);
    assert(!getuid() && !getgid());
    if (argc == 2 && !strcmp(argv[1], "--after-exec")) return 0;
    executable = argv[0];
    prefix = argc == 2 && !strcmp(argv[1], "--prefix");
    paths();
    const int modes[] = {0, CLONE_VM | CLONE_VFORK, CLONE_VFORK};
    for (unsigned i = 0; i < sizeof(modes) / sizeof(*modes); ++i) {
        for (unsigned execute = 0; execute < 2; ++execute) {
            pid_t pid = clone(child, stack + sizeof(stack), SIGCHLD | modes[i], (void*)(long)execute);
            int status;
            assert(pid > 0 && waitpid(pid, &status, 0) == pid);
            assert(WIFEXITED(status) && !WEXITSTATUS(status));
            assert(!getuid() && !getgid());
        }
    }
    puts("PASS isolated fake credentials and interpreter exec");
}
