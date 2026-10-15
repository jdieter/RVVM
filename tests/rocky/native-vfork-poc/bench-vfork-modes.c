/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Spawn-cost benchmark with resident memory and busy peers, as bench-spawn.c,
 * comparing spawn paths that run identical child code:
 *   spawn  posix_spawn (glibc: CLONE_VM|CLONE_VFORK, no TID flags)
 *   plain  clone(CLONE_VM|CLONE_VFORK|SIGCHLD)
 *   mixed  plain | CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID,
 *          the flags that need RVVM's snapshot observer
 * Trial 0 of mixed includes creating the observer. Each trial checks the
 * kernel TID stores: parent_tid == pid and child_tid cleared by the exec.
 * Usage: bench-vfork-modes resident-MiB peers launches mode program input output-prefix
 * One JSON line per trial on stdout. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;
static atomic_int stop;
static unsigned char* memory;
static size_t length;
static char child_stack[256 * 1024] __attribute__((aligned(16)));

struct launch {
    const char* program;
    char** args;
    int out;
};

static void* peer(void* arg)
{
    size_t page = (uintptr_t)arg;
    while (!atomic_load(&stop)) {
        memory[(page % (length / 4096)) * 4096]++;
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
    return NULL;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* Runs in the parent's memory until exec, like posix_spawn's child. */
static int child(void* opaque)
{
    struct launch* launch = opaque;
    if (dup2(launch->out, STDOUT_FILENO) < 0) _exit(126);
    execve(launch->program, launch->args, environ);
    _exit(127);
}

int main(int argc, char** argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: %s resident-MiB peers launches spawn|plain|mixed program input output-prefix\n",
                argv[0]);
        return 2;
    }
    length = strtoull(argv[1], NULL, 10) * 1048576;
    if (!length) length = 4096;
    unsigned peers = strtoul(argv[2], NULL, 10), launches = strtoul(argv[3], NULL, 10);
    const char* mode = argv[4];
    int flags;
    if (!strcmp(mode, "spawn")) flags = -1;
    else if (!strcmp(mode, "plain")) flags = CLONE_VM | CLONE_VFORK | SIGCHLD;
    else if (!strcmp(mode, "mixed"))
        flags = CLONE_VM | CLONE_VFORK | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID
              | CLONE_CHILD_CLEARTID | SIGCHLD;
    else return 2;
    if (peers > 96 || !launches) return 2;
    memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void* sparse = mmap(NULL, (size_t)8 << 30, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (memory == MAP_FAILED || sparse == MAP_FAILED) return 3;
    for (size_t p = 0; p < length; p += 4096) memory[p] = 1;
    pthread_t threads[96];
    for (unsigned p = 0; p < peers; p++)
        if (pthread_create(&threads[p], NULL, peer, (void*)(uintptr_t)p)) return 4;
    for (unsigned trial = 0; trial < launches; trial++) {
        char output_path[4096];
        if (snprintf(output_path, sizeof(output_path), "%s-%u", argv[7], trial) >= (int)sizeof(output_path))
            return 5;
        int out = open(output_path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
        if (out < 0) return 5;
        char* args[] = {argv[5], "-cd", argv[6], NULL};
        struct launch launch = {argv[5], args, out};
        int parent_tid = -1, child_tid = -1;
        pid_t pid;
        double start = now();
        if (flags < 0) {
            posix_spawn_file_actions_t actions;
            posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_adddup2(&actions, out, STDOUT_FILENO);
            int error = posix_spawn(&pid, argv[5], &actions, NULL, args, environ);
            posix_spawn_file_actions_destroy(&actions);
            if (error) { errno = error; perror("posix_spawn"); return 6; }
        } else {
            pid = clone(child, child_stack + sizeof(child_stack), flags, &launch,
                        &parent_tid, NULL, &child_tid);
            if (pid < 0) { perror("clone"); return 6; }
        }
        double launched = now();
        close(out);
        int status;
        struct rusage usage;
        while (wait4(pid, &status, 0, &usage) < 0) if (errno != EINTR) return 7;
        double finished = now();
        if (!WIFEXITED(status) || WEXITSTATUS(status)) return 8;
        /* The exec released the child's mm reference: Linux clears it. */
        int tids_ok = flags < 0 || !(flags & CLONE_PARENT_SETTID)
                   || (parent_tid == pid && child_tid == 0);
        if (!tids_ok) {
            fprintf(stderr, "trial %u: parent_tid=%d child_tid=%d pid=%d\n", trial, parent_tid, child_tid, pid);
            return 9;
        }
        struct rusage self;
        getrusage(RUSAGE_SELF, &self);
        printf("{\"trial\":%u,\"mode\":\"%s\",\"resident_mib\":%zu,\"peers\":%u,\"launch_s\":%.9f,"
               "\"total_s\":%.9f,\"child_user_s\":%.6f,\"child_system_s\":%.6f,\"self_maxrss_kib\":%ld}\n",
               trial, mode, length / 1048576, peers, launched - start, finished - start,
               usage.ru_utime.tv_sec + usage.ru_utime.tv_usec * 1e-6,
               usage.ru_stime.tv_sec + usage.ru_stime.tv_usec * 1e-6, self.ru_maxrss);
        fflush(stdout);
    }
    atomic_store(&stop, 1);
    for (unsigned p = 0; p < peers; p++) pthread_join(threads[p], NULL);
    munmap(memory, length);
    munmap(sparse, (size_t)8 << 30);
    return 0;
}
