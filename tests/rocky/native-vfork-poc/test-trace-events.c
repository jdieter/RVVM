/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];

static int child(void* unused)
{
    (void)unused;
    assert(syscall(SYS_getpid) == getpid());
    char* args[] = {"trace-events", "--reexec", NULL};
    char* env[] = {NULL};
    execve("/proc/self/exe", args, env);
    _exit(117);
}

int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--reexec")) _exit(23);
    int private = argc == 2 && !strcmp(argv[1], "--private");
    assert(argc == 1 || private);
    alarm(20);
    pid_t tracee = fork();
    assert(tracee >= 0);
    if (!tracee) {
        assert(!ptrace(PTRACE_TRACEME, 0, 0, 0));
        raise(SIGSTOP);
        pid_t pid = clone(child, stack + sizeof(stack), (private ? 0 : CLONE_VM) | CLONE_VFORK | SIGCHLD, NULL);
        int status;
        assert(pid > 0 && waitpid(pid, &status, 0) == pid
               && WIFEXITED(status) && WEXITSTATUS(status) == 23);
        _exit(0);
    }
    int status;
    assert(waitpid(tracee, &status, 0) == tracee && WIFSTOPPED(status));
    assert(!ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD));
    assert(!ptrace(PTRACE_CONT, tracee, 0, 0));
    unsigned vforks = 0, completed = 0, execs = 0, exits = 0, reaped = 0;
    pid_t child_pid = 0;
    unsigned child_getpid = 0;
    while (reaped < 2) {
        pid_t pid = waitpid(-1, &status, __WALL);
        assert(pid > 0);
        if (WIFEXITED(status)) {
            assert(WEXITSTATUS(status) == (pid == tracee ? 0 : 23));
            ++reaped;
            continue;
        }
        assert(WIFSTOPPED(status));
        unsigned event = (unsigned)status >> 16;
        unsigned long message;
        if (event) {
            assert(!ptrace(PTRACE_GETEVENTMSG, pid, 0, &message));
            if (event == PTRACE_EVENT_VFORK) { ++vforks; child_pid = message; }
            else if (event == PTRACE_EVENT_VFORK_DONE) { ++completed; assert(message == (unsigned)child_pid); }
            else if (event == PTRACE_EVENT_EXEC) { ++execs; assert(pid == child_pid); }
            else if (event == PTRACE_EVENT_EXIT) ++exits;
            else assert(!"unexpected tracing event");
        }
        if (pid == child_pid && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            assert(ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) > 0);
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == SYS_getpid) ++child_getpid;
        }
        if (pid == child_pid && WSTOPSIG(status) == SIGSTOP) {
            unsigned long registers[40];
            struct iovec view = {registers, sizeof(registers)};
            assert(!ptrace(PTRACE_GETREGSET, pid, 1, &view));
#if defined(__riscv)
            assert(view.iov_len == 256 && registers[0] && registers[10] == 0);
#endif
        }
        assert(!ptrace(pid == child_pid ? PTRACE_SYSCALL : PTRACE_CONT, pid, 0, 0));
    }
    assert(vforks == 1 && completed == 1 && execs == 1 && exits == 2 && child_getpid >= 1);
    puts("PASS native VFORK/exec/exit wait-event ownership");
}
