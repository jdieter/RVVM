/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

struct state { int marker, observed, parent; };
static int child(void* argument)
{
    struct state* state = argument;
    if (getppid() != state->parent) _exit(2);
    state->observed = state->marker;
    char* args[] = {"/native-vfork-definitely-missing", NULL};
    execve(args[0], args, args + 1);
    if (errno != ENOENT) _exit(3);
    _exit(0);
}
static void* thread(void* argument)
{
    struct state state = {.marker = (int)(long)argument, .parent = getpid()};
    void* stack = mmap(NULL, 65536, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    for (int i = 0; i < 32; ++i) {
        state.observed = 0;
        int pid = clone(child, (char*)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, &state);
        assert(pid > 0 && state.observed == state.marker);
        int status;
        assert(waitpid(pid, &status, 0) == pid && !status);
    }
    munmap(stack, 65536);
    return NULL;
}
int main(void)
{
    alarm(30);
    pthread_t workers[8];
    for (long i = 0; i < 8; ++i) assert(!pthread_create(&workers[i], NULL, thread, (void*)(i + 1)));
    for (int i = 0; i < 8; ++i) assert(!pthread_join(workers[i], NULL));
    puts("PASS 256 concurrent real-vfork children, TLS ownership and failed-exec writes");
}
