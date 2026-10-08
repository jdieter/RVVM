/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest pointers remain host pointers; only allocation placement differs. */
#ifndef RVVM_USER_VMA_H
#define RVVM_USER_VMA_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>
#include "user_fd_guard.h"

struct user_vma_layout {
    uintptr_t limit, top, low;
    size_t brk_window;
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

/* Ownership, rather than an address heuristic, distinguishes guest mappings
 * from the interpreter's heap, stacks and JIT. Callers serialize mutations
 * with the fd guard and mapping/heap locks. Adjacent ranges may coalesce;
 * /proc/thread-self/maps supplies the kernel VMA boundaries and permissions. */
struct user_vma_range { uintptr_t start, end; };
static struct user_vma_range* user_vma_owned;
static size_t user_vma_owned_count, user_vma_owned_capacity;
static user_fd_mutex_t user_vma_owned_lock;

static void user_vma_grow(void)
{
    if (user_vma_owned_count < user_vma_owned_capacity) return;
    size_t capacity = user_vma_owned_capacity ? user_vma_owned_capacity * 2 : 256;
    if (capacity <= user_vma_owned_capacity || capacity > SIZE_MAX / sizeof(*user_vma_owned)) abort();
    size_t bytes = capacity * sizeof(*user_vma_owned);
    /* Native metadata uses kernel mappings, not malloc: VM transitions may
     * have parked a guest thread inside the native allocator. */
    void* ranges = user_vma_owned
        ? mremap(user_vma_owned, user_vma_owned_capacity * sizeof(*user_vma_owned), bytes, MREMAP_MAYMOVE)
        : mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ranges == MAP_FAILED) abort();
    user_vma_owned = ranges;
    user_vma_owned_capacity = capacity;
}

static void user_vma_forget(uintptr_t start, size_t size)
{
    user_fd_mutex_lock(&user_vma_owned_lock);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t end = start + ((size + page - 1) & ~(page - 1));
    for (size_t i = 0; i < user_vma_owned_count;) {
        struct user_vma_range range = user_vma_owned[i];
        if (range.end <= start || range.start >= end) { ++i; continue; }
        if (range.start < start && range.end > end) {
            user_vma_grow();
            memmove(user_vma_owned + i + 2, user_vma_owned + i + 1,
                    (user_vma_owned_count - i - 1) * sizeof(range));
            user_vma_owned[i] = (struct user_vma_range){range.start, start};
            user_vma_owned[i + 1] = (struct user_vma_range){end, range.end};
            ++user_vma_owned_count;
            user_fd_mutex_unlock(&user_vma_owned_lock);
            return;
        }
        if (range.start < start) { user_vma_owned[i++].end = start; continue; }
        if (range.end > end) { user_vma_owned[i++].start = end; continue; }
        memmove(user_vma_owned + i, user_vma_owned + i + 1,
                (--user_vma_owned_count - i) * sizeof(range));
    }
    user_fd_mutex_unlock(&user_vma_owned_lock);
}

static void user_vma_remember(uintptr_t start, size_t size)
{
    user_fd_mutex_lock(&user_vma_owned_lock);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t end = start + ((size + page - 1) & ~(page - 1));
    size_t first = 0, last;
    while (first < user_vma_owned_count && user_vma_owned[first].end < start) ++first;
    last = first;
    while (last < user_vma_owned_count && user_vma_owned[last].start <= end) {
        if (user_vma_owned[last].start < start) start = user_vma_owned[last].start;
        if (user_vma_owned[last].end > end) end = user_vma_owned[last].end;
        ++last;
    }
    if (first == last) user_vma_grow();
    memmove(user_vma_owned + first + 1, user_vma_owned + last,
            (user_vma_owned_count - last) * sizeof(user_vma_owned[0]));
    user_vma_owned_count += 1;
    user_vma_owned_count -= last - first;
    user_vma_owned[first] = (struct user_vma_range){start, end};
    user_fd_mutex_unlock(&user_vma_owned_lock);
}

static int user_vma_unmap(void* addr, size_t size)
{
    int ret = munmap(addr, size);
    if (!ret) {
        user_vma_forget((uintptr_t)addr, size);
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
    /* This fallback also runs while guest writers are parked. Use stack
     * buffers: a parked peer may own libc's allocator or stdio locks. */
    int maps = open("/proc/thread-self/maps", O_RDONLY | O_CLOEXEC);
    if (maps < 0) return 0;
    char buffer[4096], line[128];
    size_t used = 0;
    uintptr_t previous = low, best = 0;
    ssize_t count;
    while ((count = read(maps, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            close(maps);
            return 0;
        }
        for (ssize_t i = 0; i < count; ++i) {
            if (buffer[i] != '\n') {
                if (used < sizeof(line) - 1) line[used++] = buffer[i];
                continue;
            }
            line[used] = 0;
            used = 0;
            char* delimiter;
            uintptr_t start = strtoull(line, &delimiter, 16);
            if (*delimiter != '-') continue;
            uintptr_t end = strtoull(delimiter + 1, NULL, 16);
            if (end <= low) continue;
            uintptr_t limit = start < high ? start : high;
            if (previous <= limit && span <= limit - previous) best = limit - span;
            if (end >= high) { previous = high; goto done; }
            if (end > previous) previous = end;
        }
    }
done:
    if (previous < high && span <= high - previous) best = high - span;
    close(maps);
    return best;
}

/* The high application range is shared by the RISC-V ASan/TSan layouts.
 * NOREPLACE arbitrates concurrent mappings with the host kernel.
 * No new userspace lock needs resetting after fork. */
static void* user_vma_map_raw(void* addr, size_t size, int prot, int flags, int fd, off_t offset)
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
        /* Keep ordinary allocations above the unmapped heap growth window.
         * Both remain in the high application range expected by sanitizers. */
        uintptr_t arena = user_vma_layout.low + user_vma_layout.brk_window * 2;
        uintptr_t floor = span <= user_vma_layout.top - arena ? arena : UINT64_C(0x10000);
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

static void* user_vma_map(void* addr, size_t size, int prot, int flags, int fd, off_t offset)
{
    void* ret = user_vma_map_raw(addr, size, prot, flags, fd, offset);
    if (ret != MAP_FAILED) user_vma_remember((uintptr_t)ret, size);
    return ret;
}

static void* user_vma_remap_raw(void* addr, size_t oldsize, size_t newsize, int flags, void* newaddr)
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
    void* dest = user_vma_map_raw(NULL, newsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (dest == MAP_FAILED) return dest;
    void* ret = mremap(addr, oldsize, newsize, flags | MREMAP_FIXED, dest);
    if (ret == MAP_FAILED) {
        int error = errno;
        munmap(dest, newsize);
        errno = error;
    }
    return ret;
}

static void* user_vma_remap(void* addr, size_t oldsize, size_t newsize, int flags, void* newaddr)
{
    void* ret = user_vma_remap_raw(addr, oldsize, newsize, flags, newaddr);
    if (ret != MAP_FAILED) {
        if (oldsize && !(flags & MREMAP_DONTUNMAP)) user_vma_forget((uintptr_t)addr, oldsize);
        user_vma_remember((uintptr_t)ret, newsize);
    }
    return ret;
}

static void* user_vma_shmat(int id, void* addr, int flags)
{
    struct shmid_ds info;
    if (shmctl(id, IPC_STAT, &info)) return (void*)-1;
    if (addr) {
        if (!user_vma_range((uintptr_t)addr, info.shm_segsz)) { errno = EINVAL; return (void*)-1; }
        void* ret = shmat(id, addr, flags);
        if (ret != (void*)-1) user_vma_remember((uintptr_t)ret, info.shm_segsz);
        return ret;
    }
    if (flags & SHM_REMAP) { errno = EINVAL; return (void*)-1; }
    void* dest = user_vma_map_raw(NULL, info.shm_segsz, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dest == MAP_FAILED) return dest;
    void* ret = shmat(id, dest, flags | SHM_REMAP);
    if (ret == (void*)-1) {
        int error = errno;
        munmap(dest, info.shm_segsz);
        errno = error;
    } else user_vma_remember((uintptr_t)ret, info.shm_segsz);
    return ret;
}

/* shmdt removes only this attachment's surviving SysV fragments. A guest may
 * have replaced an interior page with mmap; keep that replacement owned.
 * Compare kernel mapping identities, so a native allocation reusing a detached
 * hole cannot accidentally become guest memory on the next vfork. */
static int user_vma_shmdt(void* addr)
{
    struct fragment { uintptr_t start, end; unsigned long offset, inode; unsigned major, minor; };
    struct fragment *fragments = NULL;
    size_t count = 0;
    FILE* maps = fopen("/proc/thread-self/maps", "re");
    if (!maps) return -1;
    char line[4096];
    while (fgets(line, sizeof(line), maps)) {
        struct fragment range;
        if (sscanf(line, "%lx-%lx %*s %lx %x:%x %lu", &range.start, &range.end,
            &range.offset, &range.major, &range.minor, &range.inode) != 6
            || !strstr(line, "/SYSV") || (!range.inode && !range.major && !range.minor)
            || range.start < (uintptr_t)addr || range.start - (uintptr_t)addr != range.offset) continue;
        void* grown = realloc(fragments, (count + 1) * sizeof(*fragments));
        if (!grown) { fclose(maps); free(fragments); return -1; }
        fragments = grown;
        fragments[count++] = range;
    }
    int ret = shmdt(addr), saved = errno;
    if (!ret) {
        for (size_t i = 0; i < count; ++i) {
            struct fragment old = fragments[i];
            uintptr_t cursor = old.start;
            rewind(maps);
            while (fgets(line, sizeof(line), maps)) {
                struct fragment current;
                if (sscanf(line, "%lx-%lx %*s %lx %x:%x %lu", &current.start, &current.end,
                    &current.offset, &current.major, &current.minor, &current.inode) != 6
                    || current.inode != old.inode || current.major != old.major || current.minor != old.minor
                    || current.end <= old.start || current.start >= old.end) continue;
                uintptr_t start = current.start > old.start ? current.start : old.start;
                uintptr_t end = current.end < old.end ? current.end : old.end;
                if (current.offset + start - current.start != old.offset + start - old.start) continue;
                if (cursor < start) user_vma_forget(cursor, start - cursor);
                if (cursor < end) cursor = end;
            }
            if (cursor < old.end) user_vma_forget(cursor, old.end - cursor);
        }
    }
    fclose(maps);
    free(fragments);
    errno = saved;
    return ret;
}
#endif
