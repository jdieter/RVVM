/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#include "utils.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "core/rvvm_user_brk.h"

static size_t mapped_bytes(void)
{
    FILE* maps = fopen("/proc/self/statm", "r");
    size_t pages;
    assert(maps && fscanf(maps, "%zu", &pages) == 1);
    fclose(maps);
    return pages * (size_t)sysconf(_SC_PAGESIZE);
}

static void check_heap(const char* bits)
{
    assert(user_vma_init(bits));
    struct uapi_brk_heap heap = {0};
    size_t before = mapped_bytes();
    uintptr_t base = uapi_brk(&heap, 0);
    size_t page = heap.page_size;
    assert(base && mapped_bytes() == before);
    assert(uapi_brk(&heap, base + page * 2) == base + page * 2);
    unsigned char* bytes = (void*)base;
    bytes[page - 1] = 17;
    bytes[page] = 23;
    assert(uapi_brk(&heap, base + page - 1) == base + page - 1);
    assert(bytes[page - 1] == 17);
    assert(uapi_brk(&heap, base + page * 2) == base + page * 2);
    assert(bytes[page] == 0);

    void* guard = mmap((void*)(base + page * 2), page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    assert(guard == (void*)(base + page * 2));
    *(unsigned char*)guard = 99;
    assert(uapi_brk(&heap, base + page * 3) == base + page * 2);
    assert(*(unsigned char*)guard == 99);
    assert(!munmap(guard, page));
    assert(uapi_brk(&heap, UINTPTR_MAX) == base + page * 2);
    assert(uapi_brk(&heap, base - 1) == base + page * 2);

    struct rlimit saved, limit;
    assert(!getrlimit(RLIMIT_AS, &saved));
    limit = saved;
    limit.rlim_cur = mapped_bytes() + page * 2;
    assert(!setrlimit(RLIMIT_AS, &limit));
    assert(uapi_brk(&heap, base + page * 10) == base + page * 2);
    assert(!setrlimit(RLIMIT_AS, &saved));
    assert(!getrlimit(RLIMIT_DATA, &saved));
    limit = saved;
    limit.rlim_cur = 1;
    assert(!setrlimit(RLIMIT_DATA, &limit));
    assert(uapi_brk(&heap, base + page * 3) == base + page * 2);
    assert(!setrlimit(RLIMIT_DATA, &saved));

    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        bytes[0] = 42;
        assert(uapi_brk(&heap, base) == base);
        assert(uapi_brk(&heap, base + page * 2) == base + page * 2);
        assert(!bytes[0]);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && !status && !bytes[0]);
    assert(uapi_brk(&heap, base) == base);
    unsigned char resident;
    assert(mincore((void*)base, page, &resident) == -1 && errno == ENOMEM);
    assert(mapped_bytes() == before);
}

int main(void)
{
    /* Allocate ownership metadata before measuring address-space changes. */
    user_vma_grow();
    check_heap("39");
    check_heap("48");
    puts("PASS incremental heap limits, collisions, shrink/regrowth and fork isolation");
}
