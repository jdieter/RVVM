/* SPDX-License-Identifier: GPL-3.0-or-later */
/* After mixed parent/child TID VFORKs, the caller has no children left:
 * __WALL/__WCLONE waits report ECHILD instead of blocking, no task lists a
 * child, and no process still runs the pre-exec image after exec. */
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char stack[128 * 1024];
static int parent_tid, child_tid;
static char marker[64];

static int child(void* unused)
{
    (void)unused;
    _exit(0);
}

static void mixed_vfork(int vm)
{
    pid_t pid = clone(child, stack + sizeof(stack),
                      vm | CLONE_VFORK | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID
                      | CLONE_CHILD_CLEARTID | SIGCHLD, NULL, &parent_tid, NULL, &child_tid);
    assert(pid > 0 && parent_tid == pid);
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
}

static void no_children(void)
{
    int status;
    const int classes[] = {0, __WCLONE, __WALL};
    for (unsigned i = 0; i < sizeof(classes) / sizeof(*classes); ++i) {
        errno = 0;
        assert(wait4(-1, &status, WNOHANG | classes[i], NULL) == -1 && errno == ECHILD);
        siginfo_t info;
        errno = 0;
        assert(waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WNOHANG | classes[i]) == -1
               && errno == ECHILD);
    }
    /* A blocking wait must not wait for an internal process forever. */
    alarm(5);
    errno = 0;
    assert(wait4(-1, &status, __WALL, NULL) == -1 && errno == ECHILD);
    alarm(0);
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)syscall(SYS_gettid));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char list[64];
        assert(read(fd, list, sizeof(list)) == 0);
        close(fd);
    }
}

/* Another process sharing the old image keeps its command line. */
static int image_retained(void)
{
    DIR* proc = opendir("/proc");
    assert(proc);
    int found = 0;
    struct dirent* entry;
    while ((entry = readdir(proc))) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9' || atoi(entry->d_name) == getpid()) continue;
        char path[300], line[4096];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t n = read(fd, line, sizeof(line));
        close(fd);
        for (ssize_t at = 0; at < n; at += strlen(line + at) + 1)
            if (!strcmp(line + at, marker)) found = 1;
    }
    closedir(proc);
    return found;
}

int main(int argc, char** argv)
{
    /* The marker names only this run's pre-exec image, not its launcher. */
    if (argc == 1) {
        snprintf(marker, sizeof(marker), "--rvvm-observer-visibility-%ld-%ld",
                 (long)getpid(), (long)time(NULL));
        execl("/proc/self/exe", argv[0], marker, NULL);
        perror("exec");
        return 1;
    }
    if (argc == 3 && !strcmp(argv[1], "--after-exec")) {
        snprintf(marker, sizeof(marker), "%s", argv[2]);
        no_children();
        /* Allow an asynchronous internal exit to finish. */
        for (int i = 0; i < 40 && image_retained(); ++i)
            nanosleep(&(struct timespec){.tv_nsec = 50000000}, NULL);
        assert(!image_retained());
        puts("PASS mixed-TID VFORK leaves no visible children or retained pre-exec image");
        return 0;
    }
    assert(argc == 2 && !strncmp(argv[1], "--rvvm-observer-visibility-", 27));
    snprintf(marker, sizeof(marker), "%s", argv[1]);
    mixed_vfork(CLONE_VM);
    no_children();
    mixed_vfork(0);
    no_children();
    execl("/proc/self/exe", argv[0], "--after-exec", marker, NULL);
    perror("exec");
    return 1;
}
