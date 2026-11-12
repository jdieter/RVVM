/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Hold a fork child before userspace until its parent has checked proc/exe. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static void resume(pid_t pid, int signal)
{
    if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)signal) && errno != ESRCH) {
        perror("PTRACE_CONT");
        exit(1);
    }
}

int main(int argc, char** argv)
{
    assert(argc == 3 || argc == 4);
    int pipefd[2], status;
    assert(!pipe2(pipefd, O_CLOEXEC));
    pid_t parent = fork();
    assert(parent >= 0);
    if (!parent) {
        assert(dup2(pipefd[1], STDOUT_FILENO) == STDOUT_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        struct rlimit limit = {64, 64};
        assert(!setrlimit(RLIMIT_NOFILE, &limit));
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(77);
        raise(SIGSTOP);
        execl(argv[1], argv[1], argv[2], "notify", argc == 4 ? argv[3] : NULL, NULL);
        _exit(127);
    }
    close(pipefd[1]);
    assert(!fcntl(pipefd[0], F_SETFL, O_NONBLOCK));
    assert(waitpid(parent, &status, 0) == parent);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) return 77;
    assert(WIFSTOPPED(status));
    assert(!ptrace(PTRACE_SETOPTIONS, parent, NULL,
                  (void*)(PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL)));
    resume(parent, 0);
    pid_t child = 0;
    bool stopped = false, ready = false, released = false;
    for (;;) {
        char byte;
        if (read(pipefd[0], &byte, 1) == 1) ready = true;
        if (ready && stopped && !released) {
            resume(child, 0);
            released = true;
        }
        pid_t pid = waitpid(-1, &status, __WALL | WNOHANG);
        if (pid < 0) {
            if (errno == EINTR) continue;
            perror("waitpid");
            return 1;
        }
        if (!pid) { usleep(1000); continue; }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid != parent) continue;
            if (!WIFEXITED(status) || WEXITSTATUS(status) || !ready || !released) {
                fprintf(stderr, "proc/exe failed with child held before initialization\n");
                return 1;
            }
            puts("PASS proc/exe before child initialization");
            return 0;
        }
        if (!WIFSTOPPED(status)) continue;
        unsigned event = (unsigned)status >> 16;
        if (event == PTRACE_EVENT_FORK) {
            unsigned long born;
            assert(!child && !ptrace(PTRACE_GETEVENTMSG, pid, NULL, &born));
            child = born;
        }
        if (pid == child && !released) {
            stopped = true;
            continue;
        }
        int signal = WSTOPSIG(status);
        resume(pid, event || signal == SIGSTOP || signal == SIGTRAP ? 0 : signal);
    }
}
