/* SPDX-License-Identifier: GPL-3.0-or-later */
/* RVVM's internal tasks stay out of the guest's process view: /proc lists
 * no other process sharing this command line, and calls naming one (found
 * by a native helper) behave as for a nonexistent PID. Natively there is
 * no internal task. Usage: test-internal-hidden [native find-internal path] */
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static int parent_tid, child_tid;

static int child(void* unused)
{
    (void)unused;
    _exit(0);
}

static ssize_t cmdline(const char* pid, char* buffer, size_t size)
{
    char path[300];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buffer, size);
    close(fd);
    return n;
}

static long internal_pid(const char* finder)
{
    int channel[2];
    assert(!pipe(channel));
    char guest[32] = {0};
    assert(readlink("/proc/self", guest, sizeof(guest) - 1) > 0);
    pid_t pid = fork();
    if (!pid) {
        dup2(channel[1], 1);
        execl(finder, finder, guest, NULL);
        _exit(127);
    }
    close(channel[1]);
    char text[32] = {0};
    assert(read(channel[0], text, sizeof(text) - 1) > 0);
    close(channel[0]);
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    return strtol(text, NULL, 10);
}

int main(int argc, char** argv)
{
    alarm(20);
    /* Mixed parent/child TID flags make RVVM create its observer. */
    pid_t pid = clone(child, stack + sizeof(stack),
                      CLONE_VM | CLONE_VFORK | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID
                      | CLONE_CHILD_CLEARTID | SIGCHLD, NULL, &parent_tid, NULL, &child_tid);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid);

    char own[4096], other[4096];
    ssize_t length = cmdline("self", own, sizeof(own));
    assert(length > 0);
    /* Proc may number tasks in an ancestor PID namespace. */
    char self[32] = {0};
    assert(readlink("/proc/self", self, sizeof(self) - 1) > 0);
    DIR* proc = opendir("/proc");
    assert(proc);
    struct dirent* entry;
    while ((entry = readdir(proc))) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9' || !strcmp(entry->d_name, self)) continue;
        if (cmdline(entry->d_name, other, sizeof(other)) == length && !memcmp(own, other, length)) {
            fprintf(stderr, "FAIL /proc lists %s with this command line\n", entry->d_name);
            return 1;
        }
    }
    closedir(proc);

    long hidden = argc == 2 ? internal_pid(argv[1]) : 0;
    if (hidden > 0) {
        char path[64];
        errno = 0; assert(kill(hidden, 0) == -1 && errno == ESRCH);
        errno = 0; assert(kill(-hidden, 0) == -1 && errno == ESRCH);
        errno = 0; assert(getpriority(PRIO_PROCESS, hidden) == -1 && errno == ESRCH);
        errno = 0; assert(getsid(hidden) == -1 && errno == ESRCH);
        errno = 0; assert(sched_getscheduler(hidden) == -1 && errno == ESRCH);
        errno = 0; assert(waitpid(hidden, &status, WNOHANG) == -1 && errno == ECHILD);
        snprintf(path, sizeof(path), "/proc/%ld/status", hidden);
        errno = 0; assert(open(path, O_RDONLY) == -1 && errno == ENOENT);
        snprintf(path, sizeof(path), "/proc/%ld", hidden);
        errno = 0; assert(access(path, F_OK) == -1 && errno == ENOENT);
        char link[64];
        snprintf(path, sizeof(path), "/proc/%ld/exe", hidden);
        errno = 0; assert(readlink(path, link, sizeof(link)) == -1 && errno == ENOENT);
    }
    printf("PASS internal tasks hidden from /proc listings%s\n",
           hidden > 0 ? " and PID-naming calls" : " (no internal task found to probe)");
    return 0;
}
