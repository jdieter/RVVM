/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static volatile sig_atomic_t delivered;
static void handler(int signal) { assert(signal == SIGUSR1); ++delivered; }
static int child(void* unused) { (void)unused; _exit(23); }

int main(void)
{
    alarm(20);
    struct sigaction action = {.sa_handler = handler};
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1, &action, NULL));
    int signals[] = {0, SIGUSR1, SIGCHLD};
    for (unsigned shared = 0; shared < 2; ++shared) {
        for (unsigned i = 0; i < 3; ++i) {
            delivered = 0;
            pid_t pid = clone(child, stack + sizeof(stack), CLONE_VFORK
                | (shared ? CLONE_VM : 0) | signals[i], NULL);
            int status;
            assert(pid > 0 && waitpid(pid, &status, signals[i] == SIGCHLD ? 0 : __WCLONE) == pid);
            assert(WIFEXITED(status) && WEXITSTATUS(status) == 23);
            assert(delivered == (signals[i] == SIGUSR1));
        }
    }
    puts("PASS private/shared VFORK zero/custom/SIGCHLD exit signals");
}
