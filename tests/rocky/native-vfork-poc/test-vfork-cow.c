/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct state { atomic_int pid, ready, finish, ticks; };
static unsigned char* private_page;
static char child_stack[128 * 1024];

static int child(void* argument)
{
    struct state* s = argument;
    atomic_store(&s->pid, getpid());
    private_page[0] = 91;
    if (mprotect(private_page, 4096, PROT_NONE)) _exit(2);
    void* memory = mmap(NULL, 8192, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) _exit(3);
    *(unsigned char*)memory = 17;
    struct statx st;
    if (syscall(SYS_statx, AT_FDCWD, "/dev/null", 0, STATX_TYPE, &st)) _exit(4);
    unsigned char random;
    if (syscall(SYS_getrandom, &random, 1, 0) != 1) _exit(5);
    char* args[] = {"/native-vfork-cow-missing", NULL};
    execve(args[0], args, args + 1);
    if (errno != ENOENT) _exit(6);
    atomic_store(&s->ready, 1);
    while (!atomic_load(&s->finish)) atomic_fetch_add(&s->ticks, 1);
    if (*(unsigned char*)memory != 17 || munmap(memory, 8192)) _exit(7);
    _exit(0);
}

static void* controller(void* argument)
{
    struct state* s = argument;
    while (!atomic_load(&s->ready)) sched_yield();
    int pid = atomic_load(&s->pid), status;
    assert(pid > 0 && !kill(pid, SIGSTOP));
    assert(waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status));
    int before = atomic_load(&s->ticks);
    for (int i = 0; i < 100; ++i) {
        unsigned char* allocation = malloc(32768 + i);
        assert(allocation);
        allocation[32767 + i] = 1;
        free(allocation);
        void* page = mmap(NULL, 4096, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(page != MAP_FAILED && !munmap(page, 4096));
    }
    assert(before == atomic_load(&s->ticks));
    assert(private_page[0] == 37);
    assert(!kill(pid, SIGCONT));
    while (before == atomic_load(&s->ticks)) sched_yield();
    atomic_store(&s->finish, 1);
    return NULL;
}

int main(void)
{
    alarm(30);
    struct state* s = mmap(NULL, 4096, 3, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    private_page = mmap(NULL, 4096, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(s != MAP_FAILED && private_page != MAP_FAILED);
    private_page[0] = 37;
    for (int i = 0; i < 16; ++i) {
        *s = (struct state){0};
        pthread_t peer;
        assert(!pthread_create(&peer, NULL, controller, s));
        int pid = clone(child, child_stack + sizeof(child_stack), CLONE_VFORK | SIGCHLD, s);
        assert(pid > 0 && atomic_load(&s->finish) && private_page[0] == 37);
        int status;
        assert(waitpid(pid, &status, 0) == pid && !status);
        assert(!pthread_join(peer, NULL));
    }
    puts("PASS private-mm VFORK, COW/protection isolation, shared mappings, peer allocation and STOP/CONT");
}
