/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "core/rvvm_user_vm_backing.h"
#include <assert.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>

static pthread_mutex_t native_lock = PTHREAD_MUTEX_INITIALIZER;
static int allocator_ready;

static void allocator_stopped(int sig, siginfo_t* info, void* context)
{
    (void)sig;
    (void)context;
    if (info->si_syscall != SYS_mmap && info->si_syscall != SYS_brk) _exit(98);
    /* The allocation reached sysmalloc while holding its native arena lock. */
    if (write(allocator_ready, "", 1) != 1) _exit(99);
    syscall(SYS_kill, getpid(), SIGSTOP);
    _exit(100);
}

static void* allocator_thread(void* argument) { return argument; }

static void test_allocator_kill(unsigned char* guest)
{
    pthread_t prior_thread;
    assert(!pthread_create(&prior_thread, NULL, allocator_thread, NULL));
    assert(!pthread_join(prior_thread, NULL));
    void* existing = malloc(64 << 10);
    assert(existing);
    int ready[2];
    assert(!pipe(ready));
    pid_t parent = getpid();
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG, SIGKILL));
        if (getppid() != parent) _exit(95);
        close(ready[0]);
        allocator_ready = ready[1];
        /* Force libc to use arena locks after fork's single-thread reset. */
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, allocator_thread, NULL));
        assert(!pthread_join(thread, NULL));
        struct sigaction action = {.sa_sigaction = allocator_stopped, .sa_flags = SA_SIGINFO};
        assert(!sigaction(SIGSYS, &action, NULL));
        struct sock_filter code[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 1, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog filter = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
        assert(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
        assert(!syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &filter));
        guest[0] = 44;
        void* allocation = realloc(existing, 64 << 20);
        if (!allocation) _exit(97);
        _exit(96); /* The mapping trap must prevent this return. */
    }
    close(ready[1]);
    char byte;
    assert(read(ready[0], &byte, 1) == 1 && guest[0] == 44);
    assert(!kill(child, SIGKILL));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status)
           && WTERMSIG(status) == SIGKILL);
    /* This requires the parent's original arena, rather than its tcache. */
    void* surviving = malloc(64 << 10);
    assert(surviving);
    free(surviving);
    free(existing);
    close(ready[0]);
}

int main(void)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE), size = (size_t)1 << 30;
    int fd = user_vm_backing_create(size);
    assert(fd >= 0);
    assert(user_vm_backing_map(fd, NULL, page, PROT_READ, MAP_PRIVATE, 0) == MAP_FAILED && errno == EINVAL);
    assert(user_vm_backing_map(fd, NULL, page, PROT_READ, MAP_ANONYMOUS, 0) == MAP_FAILED && errno == EINVAL);
    assert(ftruncate(fd, size + page) == -1 && errno == EPERM);
    unsigned char* first = user_vm_backing_map(fd, NULL, size, PROT_READ | PROT_WRITE, 0, 0);
    unsigned char* second = user_vm_backing_map(fd, NULL, page, PROT_READ | PROT_WRITE, 0, page);
    assert(first != MAP_FAILED && second != MAP_FAILED);
    first[page] = 41;
    assert(second[0] == 41);

    /* A vfork worker has private native state, with shared guest bytes. */
    int ready[2];
    assert(!pipe(ready));
    pid_t parent = getpid();
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG, SIGKILL));
        if (getppid() != parent) _exit(95);
        close(ready[0]);
        assert(!pthread_mutex_lock(&native_lock));
        second[0] = 42;
        assert(write(ready[1], "", 1) == 1);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    assert(read(ready[0], &byte, 1) == 1);
    assert(first[page] == 42);
    assert(!kill(child, SIGKILL));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    assert(!pthread_mutex_trylock(&native_lock));
    assert(!pthread_mutex_unlock(&native_lock));
    void* allocation = malloc(1024 * 1024);
    assert(allocation);
    free(allocation);
    close(ready[0]);
    test_allocator_kill(first);

    /* Private guest mappings must be snapshotted, rather than inherited shared. */
    first[size - page] = 7;
    int copy = user_vm_backing_snapshot(fd);
    assert(copy >= 0);
    unsigned char* private = user_vm_backing_map(copy, NULL, size, PROT_READ | PROT_WRITE, 0, 0);
    assert(private != MAP_FAILED);
    assert(private[page] == 42 && private[size - page] == 7 && !private[page * 2]);
    private[page] = 99;
    first[size - page] = 8;
    assert(first[page] == 42 && private[size - page] == 7);
    struct stat info;
    assert(!fstat(copy, &info) && (uint64_t)info.st_blocks * 512 < size / 16);

    /* Changing one host alias's protection does not change the other alias.
     * The runtime must synchronize guest VMA changes separately from bytes. */
    assert(!mprotect(second, page, PROT_NONE));
    first[page] = 43;
    assert(!mprotect(second, page, PROT_READ));
    assert(second[0] == 43);
    assert(!munmap(private, size) && !munmap(second, page) && !munmap(first, size));
    close(copy);
    close(fd);
    assert(user_vm_backing_create(0) == -1 && errno == EINVAL);
    puts("PASS guest backing sharing, private snapshots and worker kill isolation");
    return 0;
}
