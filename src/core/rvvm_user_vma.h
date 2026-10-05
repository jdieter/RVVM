/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest pointers remain host pointers; only allocation placement differs. */
#ifndef RVVM_USER_VMA_H
#define RVVM_USER_VMA_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>
#include "user_fd_guard.h"

struct user_vma_layout {
    uintptr_t limit, top, low;
    size_t brk_reserve;
};

/* Select once, before guest mappings or threads exist. Both modes use the
 * same allocator; the high arenas match the RISC-V sanitizer layouts. */
static struct user_vma_layout user_vma_layout = {
    UINT64_C(0x800000000000), UINT64_C(0x7fff00000000), UINT64_C(0x7a0000000000), UINT64_C(64) << 30
};

static int user_vma_init(const char* bits)
{
    if (!bits || !strcmp(bits, "48")) return 1;
    if (strcmp(bits, "39")) return 0;
    user_vma_layout = (struct user_vma_layout) {
        UINT64_C(0x4000000000), UINT64_C(0x3fff000000), UINT64_C(0x3c00000000), UINT64_C(1) << 30
    };
    return 1;
}

static uintptr_t user_vma_cursor;

static int user_vma_unmap(void* addr, size_t size)
{
    int ret = munmap(addr, size);
    if (!ret) {
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        uintptr_t expected = (uintptr_t)addr;
        uintptr_t end = expected + ((size + page - 1) & ~(page - 1));
        /* Reuse the most recent hole instead of churning page tables. A racing
         * allocation still claims its address with NOREPLACE. */
        if (end > expected && end <= user_vma_layout.top)
            __atomic_compare_exchange_n(&user_vma_cursor, &expected, end, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
    return ret;
}

static inline int user_vma_range(uintptr_t addr, size_t size)
{
    return addr < user_vma_layout.limit && size <= user_vma_layout.limit - addr;
}

/* Callers hold the fd guard before their mapping/brk locks. The slow path
 * inspects host VMAs too: never use MAP_FIXED to claim an unowned hole. */
static uintptr_t user_vma_gap(size_t span, uintptr_t low, uintptr_t high)
{
    FILE* maps = fopen("/proc/self/maps", "re");
    if (!maps) return 0;
    char line[4096];
    uintptr_t previous = low, best = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2 || end <= low) continue;
        uintptr_t limit = start < high ? start : high;
        if (previous <= limit && span <= limit - previous) best = limit - span;
        if (end >= high) { previous = high; break; }
        if (end > previous) previous = end;
    }
    if (previous < high && span <= high - previous) best = high - span;
    fclose(maps);
    return best;
}

/* The high application range is shared by the RISC-V ASan/TSan layouts.
 * NOREPLACE arbitrates concurrent mappings with the host kernel.
 * No new userspace lock needs resetting after fork. */
static void* user_vma_map(void* addr, size_t size, int prot, int flags, int fd, off_t offset)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (!size || size > user_vma_layout.limit - page) { errno = size ? ENOMEM : EINVAL; return MAP_FAILED; }
    size_t span = (size + page - 1) & ~(page - 1);
    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        if (!user_vma_range((uintptr_t)addr, span)) { errno = ENOMEM; return MAP_FAILED; }
        return mmap(addr, size, prot, flags, fd, offset);
    }
    if (addr && user_vma_range((uintptr_t)addr, span)) {
        void* ret = mmap(addr, size, prot, flags, fd, offset);
        if (ret == MAP_FAILED || user_vma_range((uintptr_t)ret, span)) return ret;
        munmap(ret, span);
    }
    uintptr_t top = __atomic_load_n(&user_vma_cursor, __ATOMIC_RELAXED);
    if (!top) {
        uint32_t random = 0;
        if (getrandom(&random, sizeof(random), 0) != sizeof(random))
            random = (uint32_t)((uintptr_t)&random >> 4);
        uintptr_t window = (user_vma_layout.top - user_vma_layout.low) / 16;
        if (window > (UINT64_C(64) << 30)) window = UINT64_C(64) << 30;
        uintptr_t initial = user_vma_layout.top - ((uintptr_t)random % (window / page)) * page;
        __atomic_compare_exchange_n(&user_vma_cursor, &top, initial, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        top = __atomic_load_n(&user_vma_cursor, __ATOMIC_RELAXED);
    }
    if (span <= user_vma_layout.top - UINT64_C(0x10000)) {
        uintptr_t floor = span <= user_vma_layout.top - user_vma_layout.low
            ? user_vma_layout.low : UINT64_C(0x10000);
        uintptr_t next;
        do {
            next = top >= floor + span ? top - span : user_vma_layout.top - span;
        } while (!__atomic_compare_exchange_n(&user_vma_cursor, &top, next, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
        void* ret = mmap((void*)next, size, prot, flags | MAP_FIXED_NOREPLACE, fd, offset);
        if (ret != MAP_FAILED || errno != EEXIST) return ret;
    }
    for (unsigned retry = 0; retry < 128; ++retry) {
        uintptr_t next = user_vma_gap(span, UINT64_C(0x10000), user_vma_layout.top);
        if (!next) { errno = ENOMEM; return MAP_FAILED; }
        void* ret = mmap((void*)next, size, prot, flags | MAP_FIXED_NOREPLACE, fd, offset);
        if (ret != MAP_FAILED || errno != EEXIST) return ret;
    }
    errno = ENOMEM;
    return MAP_FAILED;
}

static void* user_vma_remap(void* addr, size_t oldsize, size_t newsize, int flags, void* newaddr)
{
    if (!user_vma_range((uintptr_t)addr, oldsize)
        || ((flags & MREMAP_FIXED) && !user_vma_range((uintptr_t)newaddr, newsize))) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if (!(flags & MREMAP_MAYMOVE) && !user_vma_range((uintptr_t)addr, newsize)) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if ((flags & MREMAP_FIXED) || !(flags & MREMAP_MAYMOVE))
        return mremap(addr, oldsize, newsize, flags, newaddr);
    if (!(flags & MREMAP_DONTUNMAP) && oldsize && user_vma_range((uintptr_t)addr, newsize)) {
        void* ret = mremap(addr, oldsize, newsize, flags & ~MREMAP_MAYMOVE);
        if (ret != MAP_FAILED || errno != ENOMEM) return ret;
    }
    void* dest = user_vma_map(NULL, newsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (dest == MAP_FAILED) return dest;
    void* ret = mremap(addr, oldsize, newsize, flags | MREMAP_FIXED, dest);
    if (ret == MAP_FAILED) {
        int error = errno;
        munmap(dest, newsize);
        errno = error;
    }
    return ret;
}

static void* user_vma_shmat(int id, void* addr, int flags)
{
    struct shmid_ds info;
    if (shmctl(id, IPC_STAT, &info)) return (void*)-1;
    if (addr) {
        if (!user_vma_range((uintptr_t)addr, info.shm_segsz)) { errno = EINVAL; return (void*)-1; }
        return shmat(id, addr, flags);
    }
    if (flags & SHM_REMAP) { errno = EINVAL; return (void*)-1; }
    void* dest = user_vma_map(NULL, info.shm_segsz, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dest == MAP_FAILED) return dest;
    void* ret = shmat(id, dest, flags | SHM_REMAP);
    if (ret == (void*)-1) {
        int error = errno;
        munmap(dest, info.shm_segsz);
        errno = error;
    }
    return ret;
}
#endif
