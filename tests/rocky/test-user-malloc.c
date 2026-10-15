/* SPDX-License-Identifier: GPL-3.0-or-later */
/* rvvm_user's malloc replacement: every size class and the large path,
 * aligned requests, realloc moves, errno, cross-thread frees with thread
 * exit, and both fork kinds: libc's fork() and a raw clone holding the
 * fork lock while other threads allocate. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "core/rvvm_user_malloc.h"

static void check_block(unsigned char* block, size_t size, unsigned char seed)
{
    assert(block);
    assert(malloc_usable_size(block) >= size);
    assert(((uintptr_t)block & 15) == 0);
    for (size_t i = 0; i < size; ++i) block[i] = (unsigned char)(seed + i);
}

static void check_sizes(void)
{
    static const size_t sizes[] = {0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 1000, 4095,
                                   4096, 8193, 16383, 16384, 16385, 65535, 65536, 1 << 20, 3 << 20};
    void* blocks[sizeof(sizes) / sizeof(*sizes)];
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        blocks[i] = malloc(sizes[i]);
        check_block(blocks[i], sizes[i], (unsigned char)i);
    }
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        unsigned char* block = blocks[i];
        for (size_t j = 0; j < sizes[i]; ++j) assert(block[j] == (unsigned char)(i + j));
        free(block);
    }
    unsigned char* zero = calloc(1000, 33);
    assert(zero);
    for (size_t i = 0; i < 33000; ++i) assert(!zero[i]);
    free(zero);
    /* A freed large mapping is reused: calloc must still zero it. */
    for (unsigned i = 0; i < 4; ++i) {
        unsigned char* dirty = malloc(600000);
        assert(dirty);
        memset(dirty, 0xff, 600000);
        free(dirty);
        zero = calloc(1, 590000);
        assert(zero && zero == dirty);
        for (size_t j = 0; j < 590000; ++j) assert(!zero[j]);
        free(zero);
    }
    zero = calloc(7, 9);
    for (size_t i = 0; i < 63; ++i) assert(!zero[i]);
    free(zero);
    /* Volatile: compilers may elide an unused allocation as successful. */
    volatile size_t huge = SIZE_MAX - 4096, half = SIZE_MAX / 2;
    void* volatile failed;
    errno = 0;
    failed = calloc(half, 3);
    assert(!failed && errno == ENOMEM);
    errno = 0;
    failed = malloc(huge);
    assert(!failed && errno == ENOMEM);
    free(NULL);
    assert(malloc_usable_size(NULL) == 0);
}

static void check_aligned(void)
{
    for (size_t align = 1; align <= (1 << 20); align <<= 1) {
        for (size_t size = 1; size <= (1 << 18); size = size * 7 + 3) {
            unsigned char* block = memalign(align, size);
            assert(block && ((uintptr_t)block & (align - 1)) == 0);
            check_block(block, size, 3);
            unsigned char* moved = realloc(block, size * 2 + 1);
            assert(moved);
            for (size_t i = 0; i < size; ++i) assert(moved[i] == (unsigned char)(3 + i));
            free(moved);
            void* other = NULL;
            if (align >= sizeof(void*)) {
                assert(!posix_memalign(&other, align, size));
                assert(((uintptr_t)other & (align - 1)) == 0);
                free(other);
            }
            other = aligned_alloc(align, size);
            assert(other && ((uintptr_t)other & (align - 1)) == 0);
            free(other);
        }
    }
    void* unused = (void*)1;
    assert(posix_memalign(&unused, 24, 8) == EINVAL && unused == (void*)1);
    errno = 0;
    void* volatile failed = aligned_alloc(24, 8);
    assert(!failed && errno == EINVAL);
    void* rounded = memalign(24, 8);
    assert(rounded && ((uintptr_t)rounded & 31) == 0);
    free(rounded);
    size_t page = sysconf(_SC_PAGESIZE);
    void* paged = valloc(10);
    assert(paged && ((uintptr_t)paged & (page - 1)) == 0);
    free(paged);
    paged = pvalloc(page + 1);
    assert(paged && ((uintptr_t)paged & (page - 1)) == 0 && malloc_usable_size(paged) >= 2 * page);
    free(paged);
}

static void check_realloc(void)
{
    unsigned char* block = NULL;
    size_t size = 0;
    /* Small to large and back, growing through in-place and moving remaps. */
    for (size_t next = 1; next <= (64 << 20); next = next * 3 + 1) {
        unsigned char* grown = realloc(block, next);
        assert(grown);
        for (size_t i = 0; i < size; i += 4093) assert(grown[i] == (unsigned char)i);
        for (size_t i = size; i < next; ++i) grown[i] = (unsigned char)i;
        block = grown;
        size = next;
        void* blocker = malloc(1 << 20); // occupy space after mappings
        free(blocker);
    }
    for (size_t next = size; next > 1; next /= 5) {
        block = realloc(block, next);
        assert(block);
        for (size_t i = 0; i < next; i += 4093) assert(block[i] == (unsigned char)i);
    }
    assert(realloc(block, 0) == NULL);
}

static void check_errno(void)
{
    void* small = malloc(32);
    void* large = malloc(1 << 20);
    errno = EBADF;
    free(small);
    free(large);
    assert(errno == EBADF);
    void* block = malloc(100);
    assert(errno == EBADF);
    free(block);
}

static atomic_bool stop;
static void* _Atomic exchange[64];

static void* churn(void* seed_pointer)
{
    unsigned seed = (unsigned)(uintptr_t)seed_pointer;
    while (!atomic_load(&stop)) {
        seed = seed * 1103515245 + 12345;
        size_t size = (seed >> 8) % ((seed & 0x100) ? 70000 : 600);
        unsigned char* block = malloc(size + 1);
        assert(block);
        block[0] = 1;
        block[size] = 2;
        /* Free blocks another thread allocated. */
        void* previous = atomic_exchange(&exchange[seed % 64], block);
        free(previous);
    }
    return NULL;
}

static void* short_lived(void* unused)
{
    (void)unused;
    void* blocks[200];
    for (unsigned i = 0; i < 200; ++i) blocks[i] = malloc(16 + i * 8);
    for (unsigned i = 0; i < 200; i += 2) free(blocks[i]);
    /* The odd ones outlive this thread and its cache. */
    for (unsigned i = 1; i < 200; i += 2) {
        void* previous = atomic_exchange(&exchange[i % 64], blocks[i]);
        free(previous);
    }
    return NULL;
}

static int child_work(void)
{
    for (unsigned i = 0; i < 1000; ++i) free(malloc(i * 37));
    pthread_t thread;
    if (pthread_create(&thread, NULL, short_lived, NULL) || pthread_join(thread, NULL)) return 3;
    return 7;
}

static int raw_child(void)
{
    user_malloc_fork_child();
    _exit(child_work());
}

int main(void)
{
    check_sizes();
    check_aligned();
    check_realloc();
    check_errno();
    pthread_t workers[6];
    for (unsigned i = 0; i < 6; ++i) assert(!pthread_create(&workers[i], NULL, churn, (void*)(uintptr_t)(i + 1)));
    for (unsigned round = 0; round < 64; ++round) {
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, short_lived, NULL) && !pthread_join(thread, NULL));
        /* libc's fork() runs the allocator's pthread_atfork handlers. */
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) _exit(child_work());
        int status;
        assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 7);
        /* A raw clone of this thread, with the allocator locked across it. */
        user_malloc_fork_lock();
        pid = syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, NULL);
        if (!pid) raw_child();
        user_malloc_fork_unlock();
        assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 7);
    }
    atomic_store(&stop, true);
    for (unsigned i = 0; i < 6; ++i) assert(!pthread_join(workers[i], NULL));
    for (unsigned i = 0; i < 64; ++i) free(atomic_exchange(&exchange[i], NULL));
    puts("PASS user malloc classes, alignment, realloc, errno, threads and forks");
    return 0;
}
