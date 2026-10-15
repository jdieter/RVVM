/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

struct state { int parent_tid, entered; };
static char stack[128 * 1024];
static int child(void* argument)
{
    struct state* state = argument;
    state->entered = 1;
    _exit(0);
}
static void* peer(void* argument)
{
    struct state* state = argument;
    while (!__atomic_load_n(&state->parent_tid, __ATOMIC_ACQUIRE)) sched_yield();
    void* memory = malloc(8192);
    assert(memory); free(memory);
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && !close(fd));
    struct sigaction action = {.sa_handler = SIG_IGN};
    assert(!sigaction(SIGUSR1, &action, NULL));
    assert(write(STDOUT_FILENO, "peer-ready\n", 11) == 11);
    return NULL;
}
static int workload(bool shared)
{
    struct state* state = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(state != MAP_FAILED);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, peer, state));
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VFORK | CLONE_PARENT_SETTID
        | SIGCHLD | (shared ? CLONE_VM : 0), state, &state->parent_tid);
    assert(pid > 0 && state->parent_tid == pid);
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(!pthread_join(thread, NULL));
    assert(!state->entered);
    assert(!munmap(state, 4096));
    return 0;
}
int main(int argc, char** argv)
{
    alarm(10);
    if (argc == 3 && !strcmp(argv[1], "--workload")) return workload(!strcmp(argv[2], "shared"));
    assert(argc == 4);
    int channel[2];
    assert(!pipe2(channel, O_CLOEXEC));
    pid_t parent = fork();
    assert(parent >= 0);
    if (!parent) {
        close(channel[0]);
        assert(dup2(channel[1], STDOUT_FILENO) == STDOUT_FILENO);
        close(channel[1]);
        assert(!ptrace(PTRACE_TRACEME, 0, 0, 0));
        raise(SIGSTOP);
        if (!strcmp(argv[1], "-")) execl(argv[2], argv[2], "--workload", argv[3], NULL);
        else execl(argv[1], argv[1], argv[2], "--workload", argv[3], NULL);
        _exit(127);
    }
    close(channel[1]);
    assert(!fcntl(channel[0], F_SETFL, O_NONBLOCK));
    int status;
    assert(waitpid(parent, &status, 0) == parent && WIFSTOPPED(status));
    assert(!ptrace(PTRACE_SETOPTIONS, parent, 0, PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL));
    assert(!ptrace(PTRACE_CONT, parent, 0, 0));
    pid_t stopped = 0;
    bool peer_ready = false, held = false, killed = false, parent_done = false;
    char output[64] = {0};
    size_t length = 0;
    while (!parent_done) {
        ssize_t got = read(channel[0], output + length, sizeof(output) - length - 1);
        if (got > 0) { length += got; output[length] = 0; peer_ready = strstr(output, "peer-ready\n") != NULL; }
        pid_t pid = waitpid(-1, &status, __WALL | WNOHANG);
        if (pid > 0 && WIFSTOPPED(status)) {
            unsigned event = (unsigned)status >> 16;
            if (event == PTRACE_EVENT_VFORK) {
                unsigned long message;
                assert(!ptrace(PTRACE_GETEVENTMSG, pid, 0, &message));
                stopped = message;
            }
            if (pid == stopped && WSTOPSIG(status) == SIGSTOP) held = true;
            else assert(!ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status) == SIGCHLD ? SIGCHLD : 0));
        } else if (pid == parent) {
            assert(WIFEXITED(status) && !WEXITSTATUS(status));
            parent_done = true;
        }
        if (held && peer_ready && !killed) { assert(!kill(stopped, SIGKILL)); killed = true; }
        usleep(1000);
    }
    assert(held && peer_ready && killed);
    close(channel[0]);
    puts("PASS parent peer progress while child is stopped before its first callback");
}
