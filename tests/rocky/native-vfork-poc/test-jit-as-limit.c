/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A guest that caps its address space (RLIMIT_AS) leaves no room for new
 * threads' JIT code caches, as glibc's malloc/tst-malloc-thread-fail does:
 * those threads run interpreted, and nothing may appear on the guest's
 * stderr. Caps the address space above current use, fills the cap with
 * mappings, leaving room for new threads but not for a 16 MiB JIT cache,
 * then starts threads that compute and checks their results and that
 * nothing was written to stderr meanwhile. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>

#define THREADS 6

static unsigned long mapped(void)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) { perror("maps"); exit(1); }
    char line[512];
    unsigned long total = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) total += end - start;
    }
    fclose(maps);
    return total;
}

static void* work(void* opaque)
{
    unsigned long n = (unsigned long)opaque, sum = 0;
    for (unsigned long i = 0; i < 2000000; ++i) sum += (i ^ n) % 7;
    return (void*)sum;
}

int main(void)
{
    unsigned long expect[THREADS];
    for (int i = 0; i < THREADS; ++i) expect[i] = (unsigned long)work((void*)(unsigned long)i);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    struct rlimit limit;
    limit.rlim_cur = limit.rlim_max = mapped() + (200UL << 20);
    if (setrlimit(RLIMIT_AS, &limit)) { perror("setrlimit"); return 1; }
    /* Fill the cap in 1 MiB steps, then give back 10 MiB: room for new
     * threads in the guest and the emulator, not for a JIT cache. */
    size_t filled = 0;
    void* recent[10] = {0};
    void* map;
    while ((map = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) != MAP_FAILED) {
        recent[(filled >> 20) % 10] = map;
        filled += 1 << 20;
    }
    for (int i = 0; i < 10; ++i) if (recent[i]) munmap(recent[i], 1 << 20);
    if (filled < (100UL << 20)) { printf("FAIL filled only %zu MiB under the cap\n", filled >> 20); return 1; }
    /* The emulator shares the guest's descriptors: catch its stderr. */
    int err_pipe[2], saved_err = dup(2);
    if (saved_err < 0 || pipe2(err_pipe, O_NONBLOCK)) { perror("pipe"); return 1; }
    dup2(err_pipe[1], 2);
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; ++i) {
        int err = pthread_create(&threads[i], &attr, work, (void*)(unsigned long)i);
        if (err) { printf("FAIL pthread_create: %s\n", strerror(err)); return 1; }
    }
    for (int i = 0; i < THREADS; ++i) {
        void* result;
        pthread_join(threads[i], &result);
        if ((unsigned long)result != expect[i]) { printf("FAIL thread %d computed %lu, not %lu\n", i, (unsigned long)result, expect[i]); return 1; }
    }
    dup2(saved_err, 2);
    char text[256];
    ssize_t len = read(err_pipe[0], text, sizeof(text) - 1);
    if (len > 0) {
        text[len] = 0;
        printf("FAIL written to stderr: %s", text);
        return 1;
    }
    puts("PASS threads under a tight RLIMIT_AS ran correctly, with nothing on stderr");
    return 0;
}
