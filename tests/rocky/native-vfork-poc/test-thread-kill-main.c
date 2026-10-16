/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Other threads signal the main thread with pthread_kill, as glibc's
 * tst-mallocfork3 does, while it allocates and forks. pthread_kill sends
 * tgkill(getpid(), main thread's TID): both must stay valid throughout.
 * glibc's test driver runs each test in a forked child, so the test runs
 * both directly and in a fork child, whose cached TID libc's fork stored
 * through CLONE_CHILD_SETTID. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_t main_thread;
static volatile sig_atomic_t received;
static volatile int stop, failure;

static void on_usr1(int sig)
{
    (void)sig;
    ++received;
}

static void* sender(void* unused)
{
    (void)unused;
    while (!stop) {
        int error = pthread_kill(main_thread, SIGUSR1);
        if (error) {
            failure = error;
            fprintf(stderr, "pthread_kill: %s (sender getpid %d, gettid %ld)\n",
                    strerror(error), getpid(), syscall(SYS_gettid));
            return NULL;
        }
        usleep(100);
    }
    return NULL;
}

static int run(void)
{
    stop = failure = 0;
    main_thread = pthread_self();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_usr1;
    action.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &action, NULL);
    pid_t pid = getpid();
    long tid = syscall(SYS_gettid);
    if (pid != tid) {
        printf("FAIL main thread: getpid %d != gettid %ld\n", pid, tid);
        return 1;
    }
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) pthread_create(&threads[i], NULL, sender, NULL);
    for (int round = 0; round < 200 && !failure; ++round) {
        free(malloc(1 + round * 37));
        pid_t child = fork();
        if (child == 0) _exit(0);
        int status;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        if (!WIFEXITED(status) || WEXITSTATUS(status)) { failure = -1; break; }
    }
    stop = 1;
    for (int i = 0; i < 4; ++i) pthread_join(threads[i], NULL);
    if (failure) {
        printf("FAIL pthread_kill of the main thread: %s (main pid %d, tid %ld)\n",
               failure > 0 ? strerror(failure) : "fork child failed", pid, tid);
        return 1;
    }
    return 0;
}

int main(void)
{
    alarm(60);
    if (run()) return 1;
    int direct = received;
    received = 0;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) _exit(run());
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) {
        printf("FAIL in a fork child (status 0x%x)\n", status);
        return 1;
    }
    printf("PASS other threads signal the main thread during forks, directly and in a fork child "
           "(%d received directly)\n", direct);
    return 0;
}
