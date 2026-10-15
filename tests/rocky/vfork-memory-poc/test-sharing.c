/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned char *memory;
static int pipes[2], mode;
static void *peer(void *unused)
{
    (void)unused;
    while (memory[0] != 17) sched_yield();
    memory[4096] = 29;
    assert(write(pipes[1], "K", 1) == 1);
    return NULL;
}
static int child(void *unused)
{
    (void)unused;
    memory[0] = 17;
    if (mode == 0) {
        /* A kernel writer must fault in an untouched shared guest page. */
        if (read(pipes[0], (void *)(memory + 8192), 1) != 1) _exit(11);
        if (memory[4096] != 29 || memory[8192] != 'K') _exit(12);
        if (mprotect((void *)(memory + 12288), 4096, PROT_READ | PROT_WRITE)) _exit(13);
        memory[12288] = 37;
    } else if (mode == 1) {
        char *args[] = {"/vfork-poc-nonexistent", NULL};
        execve(args[0], args, args + 1);
        memory[4096] = errno;
    } else {
        kill(getpid(), SIGKILL);
        _exit(14);
    }
    _exit(0);
}
int main(void)
{
    memory = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED && stack != MAP_FAILED);
    assert(!pipe(pipes));
    for (mode = 0; mode < 3; mode++) {
        memory[0] = memory[4096] = 0;
        assert(!mprotect((void *)(memory + 12288), 4096, PROT_READ));
        pthread_t thread;
        if (mode == 0) assert(!pthread_create(&thread, NULL, peer, NULL));
        pid_t pid = clone(child, (char *)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        assert(pid > 0 && memory[0] == 17);
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        if (mode == 0) {
            assert(!status && memory[4096] == 29 && memory[8192] == 'K' && memory[12288] == 37);
            assert(!pthread_join(thread, NULL));
        } else if (mode == 1) assert(!status && memory[4096] == ENOENT);
        else assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        /* Restoring a vfork mapping must also restore ordinary fork COW. */
        memory[0] = 41;
        pid = fork();
        assert(pid >= 0);
        if (!pid) { memory[0] = 99; _exit(0); }
        assert(waitpid(pid, &status, 0) == pid && !status && memory[0] == 41);
    }
    puts("PASS kernel writes, parent concurrency, RO->RW, failed exec, SIGKILL, ordinary fork");
    return 0;
}
