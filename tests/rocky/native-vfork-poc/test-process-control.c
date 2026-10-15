/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct context {
    int pid;
    int publish_pid;
    atomic_ulong counter;
    atomic_int mode, error;
};

static void pause_ms(long ms)
{
    struct timespec t = {.tv_sec = ms / 1000, .tv_nsec = ms % 1000 * 1000000};
    nanosleep(&t, NULL);
}

static int child(void* argument)
{
    struct context* c = argument;
    if (c->publish_pid) __atomic_store_n(&c->pid, getpid(), __ATOMIC_RELEASE);
    if (!atomic_load(&c->mode)) {
        for (;;) atomic_fetch_add_explicit(&c->counter, 1, memory_order_relaxed);
    }
    unsigned char bytes[4096] = {0};
    struct open_how* how = (void*)bytes;
    how->flags = O_RDONLY;
    for (;;) {
        if (atomic_load(&c->mode) == 2) {
            void* page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page == MAP_FAILED) atomic_store(&c->error, 1);
            else {
                *(volatile unsigned char*)page = 1;
                if (munmap(page, 4096)) atomic_store(&c->error, 1);
            }
        } else {
            int fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", how, sizeof(bytes));
            if (fd < 0) atomic_store(&c->error, 1);
            else close(fd);
        }
        atomic_fetch_add(&c->counter, 1);
    }
}

static void* control(void* argument)
{
    struct context* c = argument;
    unsigned waits = 0;
    while (!__atomic_load_n(&c->pid, __ATOMIC_ACQUIRE) || !atomic_load(&c->counter)) {
        assert(++waits < 10000);
        pause_ms(1);
    }
    if (!atomic_load(&c->mode)) {
        assert(!kill(c->pid, SIGSTOP));
        int status;
        assert(waitpid(c->pid, &status, WUNTRACED) == c->pid && WIFSTOPPED(status));
        unsigned long before = atomic_load(&c->counter);
        pause_ms(50);
        assert(before == atomic_load(&c->counter));
        assert(!kill(c->pid, SIGCONT));
        waits = 0;
        while (before == atomic_load(&c->counter)) {
            assert(++waits < 10000);
            pause_ms(1);
        }
        pause_ms(150);
    } else {
        /* Child death during kernel-backed openat2 must not strand a shared
         * native allocator lock. The controller keeps allocating afterwards. */
        for (int i = 0; i < 100; ++i) {
            size_t n = 32768 + i * 13;
            volatile unsigned char* memory = malloc(n);
            assert(memory);
            memory[0] = 1;
            memory[n - 1] = 2;
            free((void*)memory);
        }
        pause_ms(20);
    }
    assert(!kill(c->pid, SIGKILL));
    for (int i = 0; i < 100; ++i) {
        volatile unsigned char* memory = malloc(65536);
        assert(memory);
        memory[0] = 3;
        free((void*)memory);
    }
    return NULL;
}

int main(int argc, char** argv)
{
    int publish_pid = argc == 2 && !strcmp(argv[1], "--guest-publish");
    assert(argc == 1 || publish_pid);
    alarm(30);
    FILE* status_file = fopen("/proc/self/status", "r");
    assert(status_file && geteuid() != 0);
    char line[256];
    int capability_checked = 0;
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "CapEff:", 7)) continue;
        assert(strtoull(line + 7, NULL, 16) == 0);
        capability_checked = 1;
    }
    fclose(status_file);
    assert(capability_checked);
    printf("credentials uid=%u gid=%u CapEff=0\n", getuid(), getgid());
    const size_t size = 1024 * 1024;
    void* stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    for (int iteration = 0; iteration < 21; ++iteration) {
        struct context c = {.publish_pid = publish_pid,
                            .mode = !iteration ? 0 : iteration <= 10 ? 1 : 2};
        pthread_t controller;
        assert(!pthread_create(&controller, NULL, control, &c));
        int pid = clone(child, (char*)stack + size,
                        CLONE_VM | CLONE_VFORK | (publish_pid ? 0 : CLONE_PARENT_SETTID) | SIGCHLD,
                        &c, &c.pid, NULL, NULL);
        assert(pid > 0 && pid == c.pid);
        int status;
        struct rusage usage;
        assert(wait4(pid, &status, 0, &usage) == pid);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        assert(!pthread_join(controller, NULL));
        assert(!atomic_load(&c.error));
        if (!iteration) {
            long us = usage.ru_utime.tv_sec * 1000000 + usage.ru_utime.tv_usec
                    + usage.ru_stime.tv_sec * 1000000 + usage.ru_stime.tv_usec;
            assert(us > 10000);
            printf("child_cpu_us=%ld counter=%lu\n", us, atomic_load(&c.counter));
        }
    }
    munmap(stack, size);
    puts("PASS actual child STOP/CONT, CPU accounting, SIGKILL allocator/mapping liveness");
}
