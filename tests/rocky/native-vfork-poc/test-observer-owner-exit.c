#define _GNU_SOURCE
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_int* state;

static void* peer(void* unused)
{
    (void)unused;
    atomic_store(state, 1);
    while (atomic_load(state) != 2) sched_yield();
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}

int main(void)
{
    alarm(5);
    state = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(state != MAP_FAILED);
    atomic_store(&state[1], 1);
    pid_t owner = fork();
    assert(owner >= 0);
    if (!owner) {
        assert(syscall(SYS_set_tid_address, &state[1]) > 0);
        pthread_t thread;
        assert(pthread_create(&thread, NULL, peer, NULL) == 0);
        while (!atomic_load(state)) sched_yield();
        syscall(SYS_exit, 0);
        __builtin_unreachable();
    }
    int pidfd = syscall(SYS_pidfd_open, owner, 0);
    assert(pidfd >= 0);
    while (!atomic_load(state)) sched_yield();
    while (atomic_load(&state[1])) sched_yield();
    struct pollfd pollfd = {.fd = pidfd, .events = POLLIN};
    /* The initial guest thread can exit while peers retain the owning mm. */
    assert(poll(&pollfd, 1, 100) == 0);
    atomic_store(state, 2);
    assert(poll(&pollfd, 1, 2000) == 1 && (pollfd.revents & POLLIN));
    int status;
    assert(waitpid(owner, &status, 0) == owner && WIFEXITED(status));
    close(pidfd);
    puts("PASS: owner pidfd becomes readable only after the last thread exits");
    return 0;
}
