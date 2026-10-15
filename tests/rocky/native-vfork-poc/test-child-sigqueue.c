/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static int child(void* unused)
{
    (void)unused;
    pid_t pid = getpid(), tid = syscall(SYS_gettid);
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask, SIGRTMIN);
    assert(!sigprocmask(SIG_BLOCK, &mask, NULL));
    siginfo_t sent = {.si_signo = SIGRTMIN, .si_code = SI_QUEUE};
    sent.si_pid = pid; sent.si_uid = getuid();
    for (unsigned thread = 0; thread < 2; ++thread) {
        sent.si_value.sival_int = 91 + thread;
        long ret = thread
            ? syscall(SYS_rt_tgsigqueueinfo, pid, tid, SIGRTMIN, &sent)
            : syscall(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &sent);
        assert(!ret);
        siginfo_t got;
        const struct timespec timeout = {.tv_sec = 1};
        assert(sigtimedwait(&mask, &got, &timeout) == SIGRTMIN);
        assert(got.si_code == SI_QUEUE && got.si_pid == pid && got.si_uid == sent.si_uid
            && got.si_value.sival_int == sent.si_value.sival_int);
    }
    errno = 0;
    assert(syscall(SYS_rt_sigqueueinfo, pid, SIGRTMIN, (void*)1) == -1 && errno == EFAULT);
    errno = 0;
    assert(syscall(SYS_rt_tgsigqueueinfo, pid, tid, SIGRTMIN, (void*)1) == -1 && errno == EFAULT);
    _exit(0);
}

int main(void)
{
    alarm(10);
    for (unsigned shared = 0; shared < 2; ++shared) {
        pid_t pid = clone(child, stack + sizeof(stack),
            SIGCHLD | (shared ? CLONE_VM | CLONE_VFORK : 0), NULL);
        int status;
        assert(pid > 0 && waitpid(pid, &status, 0) == pid);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    puts("PASS process/thread queued signals in ordinary and shared-mm children");
}
