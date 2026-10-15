/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static atomic_int stop;
static unsigned char *memory;
static size_t length;
static void *peer(void *arg)
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
int main(int argc, char **argv)
{
    if (argc != 7 && argc != 8) {
        fprintf(stderr, "usage: %s resident-MiB peers launches xz input output [readonly-file]\n", argv[0]);
        return 2;
    }
    length = strtoull(argv[1], NULL, 10) * 1048576;
    if (!length) length = 4096;
    unsigned peers = strtoul(argv[2], NULL, 10), launches = strtoul(argv[3], NULL, 10);
    if (peers > 96 || !launches) return 2;
    memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *sparse = mmap(NULL, (size_t)8 << 30, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (memory == MAP_FAILED || sparse == MAP_FAILED) return 3;
    for (size_t p = 0; p < length; p += 4096) memory[p] = 1;
    if (argc == 8) {
        int fd = open(argv[7], O_RDONLY);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) || !st.st_size) return 3;
        volatile unsigned char *file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (file == MAP_FAILED) return 3;
        volatile unsigned char checksum = 0;
        for (size_t p = 0; p < (size_t)st.st_size; p += 4096) checksum ^= file[p];
        fprintf(stderr, "readonly-mapping bytes=%ld checksum=%u\n", (long)st.st_size, checksum);
        close(fd);
    }
    pthread_t threads[96];
    for (unsigned p = 0; p < peers; p++)
        if (pthread_create(&threads[p], NULL, peer, (void *)(uintptr_t)p)) return 4;
    for (unsigned trial = 0; trial < launches; trial++) {
        char output_path[4096];
        if (snprintf(output_path, sizeof(output_path), "%s-%u", argv[6], trial) >= (int)sizeof(output_path)) return 5;
        int out = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (out < 0) return 5;
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, out, STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&actions, out);
        char *args[] = {argv[4], "-cd", argv[5], NULL};
        pid_t child;
        struct rusage before;
        getrusage(RUSAGE_CHILDREN, &before);
        double start = now();
        int error = posix_spawn(&child, argv[4], &actions, NULL, args, environ);
        double launched = now();
        close(out);
        posix_spawn_file_actions_destroy(&actions);
        if (error) { errno = error; perror("posix_spawn"); return 6; }
        int status;
        struct rusage usage;
        while (wait4(child, &status, 0, &usage) < 0) if (errno != EINTR) return 7;
        if (!WIFEXITED(status) || WEXITSTATUS(status)) return 8;
        struct rusage self, children;
        getrusage(RUSAGE_SELF, &self);
        getrusage(RUSAGE_CHILDREN, &children);
        printf("{\"trial\":%u,\"resident_mib\":%zu,\"peers\":%u,\"launch_s\":%.9f,\"total_s\":%.9f,\"child_user_s\":%.6f,\"child_system_s\":%.6f,\"self_maxrss_kib\":%ld,\"child_maxrss_kib\":%ld,\"child_minflt\":%ld,\"child_majflt\":%ld}\n",
               trial, length / 1048576, peers, launched - start, now() - start,
               usage.ru_utime.tv_sec + usage.ru_utime.tv_usec * 1e-6,
               usage.ru_stime.tv_sec + usage.ru_stime.tv_usec * 1e-6,
               self.ru_maxrss, usage.ru_maxrss, usage.ru_minflt, usage.ru_majflt);
        fflush(stdout);
        fprintf(stderr, "aggregate-child-cpu trial=%u user=%.6f system=%.6f self-user=%.6f self-system=%.6f\n", trial,
                children.ru_utime.tv_sec - before.ru_utime.tv_sec
                    + (children.ru_utime.tv_usec - before.ru_utime.tv_usec) * 1e-6,
                children.ru_stime.tv_sec - before.ru_stime.tv_sec
                    + (children.ru_stime.tv_usec - before.ru_stime.tv_usec) * 1e-6,
                self.ru_utime.tv_sec + self.ru_utime.tv_usec * 1e-6,
                self.ru_stime.tv_sec + self.ru_stime.tv_usec * 1e-6);
    }
    atomic_store(&stop, 1);
    for (unsigned p = 0; p < peers; p++) pthread_join(threads[p], NULL);
    munmap(memory, length);
    munmap(sparse, (size_t)8 << 30);
    return 0;
}
