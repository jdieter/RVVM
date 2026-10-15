/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    alarm(5);
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        assert(!ptrace(PTRACE_TRACEME, 0, 0, 0));
        raise(SIGSTOP);
        for (;;) pause();
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status));
    assert(!ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL));
    assert(!ptrace(PTRACE_CONT, pid, 0, 0));
    assert(!kill(pid, SIGKILL));
    assert(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status)
        && (unsigned)status >> 16 == PTRACE_EVENT_EXIT);
    unsigned long registers[40];
    struct iovec view = {registers, sizeof(registers)};
    assert(!ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &view));
    unsigned long saved[40];
    memcpy(saved, registers, view.iov_len);
    /* Group exit consumes SIGKILL and drops subsequent signals. */
    assert(!kill(pid, SIGKILL));
    assert(!ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &view));
    assert(!memcmp(saved, registers, view.iov_len));
    assert(!ptrace(PTRACE_CONT, pid, 0, 0));
    assert(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    puts("PASS exit-stop registers stay stable after repeated SIGKILL");
}
