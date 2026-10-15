/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char stack[128 * 1024];
static atomic_int started, finish;
static int children_fd, observed, stopped_before_start;

static int child(void* unused)
{
    (void)unused;
    atomic_store(&started, 1);
    while (!atomic_load(&finish)) {}
    _exit(0);
}

static void* control(void* unused)
{
    (void)unused;
    char bytes[256];
    for (unsigned tries = 0; tries < 1000000 && !observed; ++tries) {
        assert(lseek(children_fd, 0, SEEK_SET) == 0);
        ssize_t n = read(children_fd, bytes, sizeof(bytes) - 1);
        assert(n >= 0);
        bytes[n] = 0;
        observed = atoi(bytes);
    }
    assert(observed > 0 && !kill(observed, SIGSTOP));
    int status;
    assert(waitpid(observed, &status, WUNTRACED) == observed && WIFSTOPPED(status));
    stopped_before_start = !atomic_load(&started);
    /* These operations must not need the stopped child to acknowledge that
     * the kernel has already copied its files and signal dispositions. */
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && !close(fd));
    struct sigaction action = {.sa_handler = SIG_IGN};
    assert(!sigaction(SIGUSR1, &action, NULL));
    atomic_store(&finish, 1);
    assert(!kill(observed, SIGCONT));
    return NULL;
}

int main(void)
{
    alarm(10);
    cpu_set_t available, singleton;
    assert(!sched_getaffinity(0, sizeof(available), &available));
    int cpu = 0;
    while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &available)) ++cpu;
    assert(cpu < CPU_SETSIZE);
    CPU_ZERO(&singleton); CPU_SET(cpu, &singleton);
    assert(!sched_setaffinity(0, sizeof(singleton), &singleton));
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/children", syscall(SYS_gettid));
    children_fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(children_fd >= 0);
    char before[256];
    assert(read(children_fd, before, sizeof(before)) == 0);
    pthread_t controller;
    assert(!pthread_create(&controller, NULL, control, NULL));
    assert(!setpriority(PRIO_PROCESS, syscall(SYS_gettid), 19));
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && !status);
    assert(!pthread_join(controller, NULL) && observed == pid);
    printf("PASS stopped child permits parent FD/action operations; early=%d\n", stopped_before_start);
    close(children_fd);
    return 0;
}
