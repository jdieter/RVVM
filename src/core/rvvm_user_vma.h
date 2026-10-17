/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest pointers remain host pointers; only allocation placement differs. */
#ifndef RVVM_USER_VMA_H
#define RVVM_USER_VMA_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>
#include "user_fd_guard.h"
#include "user_proc_read.h"

#include <sys/syscall.h>
static THREAD_LOCAL long (*user_vma_executor)(long, long, long, long, long, long, long);
static long user_vma_execute(long nr, long a, long b, long c, long d, long e, long f)
{
    if (!user_vma_executor) return syscall(nr, a, b, c, d, e, f);
    long ret = user_vma_executor(nr, a, b, c, d, e, f);
    if ((unsigned long)ret >= (unsigned long)-4095) { errno = -ret; return -1; }
    return ret;
}

/* Guest execute permission asks the host for EXEC too (see rvvm_sys_prot),
 * so kernel maps, including the guest's /proc/self/maps, show it. Guest code
 * is only decoded and translated, never run by the host, so EXEC is never
 * required. Where it is refused, map or protect without it: prctl MDWE
 * (systemd MemoryDenyWriteExecute on Linux 6.3+) and SELinux execmem deny
 * with EACCES; systemd's older seccomp filter and noexec mounts with EPERM.
 * Unrelated errors recur without EXEC. The execute registry stays
 * authoritative. Accepting noexec files matches earlier rvvm_user, which
 * never asked for EXEC, so sysroots on /tmp or /dev/shm keep working; a
 * RISC-V kernel would refuse them. */
static bool user_vma_exec_refused(int prot)
{
    return (prot & PROT_EXEC) && (errno == EACCES || errno == EPERM);
}

static void* user_vma_kernel_map(void* addr, size_t size, int prot, int flags, int fd, off_t offset)
{
    void* ret = (void*)user_vma_execute(SYS_mmap, (long)addr, size, prot, flags, fd, offset);
    if (ret == MAP_FAILED && user_vma_exec_refused(prot))
        ret = (void*)user_vma_execute(SYS_mmap, (long)addr, size, prot & ~PROT_EXEC, flags, fd, offset);
    return ret;
}

/* As user_vma_kernel_map. Sets *prot to the protection last requested. */
static int user_vma_kernel_protect(void* addr, size_t size, int* prot)
{
    int ret = (int)user_vma_execute(SYS_mprotect, (long)addr, size, *prot, 0, 0, 0);
    if (ret && user_vma_exec_refused(*prot)) {
        *prot &= ~PROT_EXEC;
        ret = (int)user_vma_execute(SYS_mprotect, (long)addr, size, *prot, 0, 0, 0);
    }
    return ret;
}

#define user_vma_kernel_unmap(a,b) ((int)user_vma_execute(SYS_munmap,(long)(a),b,0,0,0,0))
#define user_vma_kernel_remap(a,b,c,d,e) ((void*)user_vma_execute(SYS_mremap,(long)(a),b,c,d,(long)(e),0))
#define user_vma_kernel_valid(fd) user_vma_execute(SYS_fcntl,fd,F_GETFD,0,0,0,0)
/* SysV permission checks and IPC namespaces follow the calling process. */
#define user_vma_kernel_shmctl(a,b,c) ((int)user_vma_execute(SYS_shmctl,a,b,(long)(c),0,0,0))
#define user_vma_kernel_shmat(a,b,c) ((void*)user_vma_execute(SYS_shmat,a,(long)(b),c,0,0,0))
#define user_vma_kernel_shmdt(a) ((int)user_vma_execute(SYS_shmdt,(long)(a),0,0,0,0,0))

struct user_vma_layout {
    uintptr_t limit, top, low;
    size_t brk_window;
};

/* Select once, before guest mappings or threads exist. Both modes use the
 * same allocator; the high arenas match the RISC-V sanitizer layouts. */
static struct user_vma_layout user_vma_layout = {
    UINT64_C(0x800000000000), UINT64_C(0x7fff00000000), UINT64_C(0x7a0000000000), UINT64_C(64) << 30
};
static size_t user_vma_huge_page;

/* Base page size is fixed for this host. Avoid repeated libc queries in the
 * mapping path; native fixtures can also initialize it before user_vma_init. */
static size_t user_vma_page(void)
{
    static size_t cached;
    size_t page = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (!page) {
        page = (size_t)sysconf(_SC_PAGESIZE);
        __atomic_store_n(&cached, page, __ATOMIC_RELAXED);
    }
    return page;
}

static int user_vma_init(const char* bits)
{
    if (bits && strcmp(bits, "39") && strcmp(bits, "48")) return 0;
    if (bits && !strcmp(bits, "39"))
        user_vma_layout = (struct user_vma_layout) {
            UINT64_C(0x4000000000), UINT64_C(0x3fff000000), UINT64_C(0x3c00000000), UINT64_C(1) << 30
        };
    /* Cache the kernel's default before guests can exhaust descriptor slots. */
    int fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char info[4096];
        ssize_t count = read(fd, info, sizeof(info) - 1);
        close(fd);
        if (count > 0) {
            info[count] = 0;
            char* value = strstr(info, "Hugepagesize:");
            if (value) user_vma_huge_page = strtoul(value + 13, NULL, 10) * 1024;
        }
    }
    return 1;
}

static size_t user_vma_map_page(int flags)
{
    size_t page = user_vma_page();
#ifdef MAP_HUGETLB
    if (flags & MAP_HUGETLB) {
        unsigned shift = ((unsigned)flags >> 26) & 63;
        size_t huge = shift ? (size_t)1 << shift : user_vma_huge_page;
        if (!huge) return 0;
        if (huge > page) page = huge;
    }
#endif
    return page;
}

static uintptr_t user_vma_cursor;

/* The guest's main stack grows down into [low, high) on demand, as Linux's
 * does into the gap it leaves above mmap_base. Placement never chooses this
 * range, so it stays free; only fixed or hinted guest mappings enter it. */
static uintptr_t user_vma_stack_low, user_vma_stack_high;

static inline bool user_vma_stack_overlaps(uintptr_t start, size_t span)
{
    return start < user_vma_stack_high && start + span > user_vma_stack_low;
}

/* Ownership, rather than an address heuristic, distinguishes guest mappings
 * from the interpreter's heap, stacks and JIT. Callers serialize mutations
 * with the fd guard and mapping/heap locks. Adjacent ranges may coalesce;
 * /proc/thread-self/maps supplies the kernel VMA boundaries and permissions. */
struct user_vma_range { uintptr_t start, end; };
static struct user_vma_range* user_vma_owned;
static size_t user_vma_owned_count, user_vma_owned_capacity;
static user_fd_mutex_t user_vma_owned_lock;

static bool user_vma_reserve_locked(size_t extra)
{
    if (extra <= user_vma_owned_capacity - user_vma_owned_count) return true;
    size_t capacity = user_vma_owned_capacity ? user_vma_owned_capacity * 2 : 256;
    if (extra > SIZE_MAX - user_vma_owned_count) { errno = ENOMEM; return false; }
    if (capacity < user_vma_owned_count + extra) capacity = user_vma_owned_count + extra;
    if (capacity <= user_vma_owned_capacity || capacity > SIZE_MAX / sizeof(*user_vma_owned)) {
        errno = ENOMEM;
        return false;
    }
    size_t bytes = capacity * sizeof(*user_vma_owned);
    /* Native metadata uses kernel mappings, not malloc: VM transitions may
     * have parked a guest thread inside the native allocator. */
    void* ranges = user_vma_owned
        ? mremap(user_vma_owned, user_vma_owned_capacity * sizeof(*user_vma_owned), bytes, MREMAP_MAYMOVE)
        : mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ranges == MAP_FAILED) return false;
    user_vma_owned = ranges;
    user_vma_owned_capacity = capacity;
    return true;
}

static bool user_vma_reserve(size_t extra)
{
    user_fd_mutex_lock(&user_vma_owned_lock);
    bool result = user_vma_reserve_locked(extra);
    user_fd_mutex_unlock(&user_vma_owned_lock);
    return result;
}

static void user_vma_grow(void)
{
    /* Mutating callers reserve metadata before changing kernel mappings.
     * A failure here therefore indicates a broken ownership invariant. */
    if (!user_vma_reserve_locked(1)) abort();
}

static void user_vma_forget(uintptr_t start, size_t size)
{
    user_fd_mutex_lock(&user_vma_owned_lock);
    size_t page = user_vma_page();
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
    size_t page = user_vma_page();
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
    uintptr_t start = (uintptr_t)addr;
    size_t page = user_vma_page();
    if (!size || start % page || size > SIZE_MAX - page + 1
        || start > SIZE_MAX - ((size + page - 1) & ~(page - 1)))
        return user_vma_kernel_unmap(addr, size);
    if (size <= SIZE_MAX - page + 1) {
        uintptr_t end = start + ((size + page - 1) & ~(page - 1));
        for (size_t i = 0; i < user_vma_owned_count; ++i) {
            if (user_vma_owned[i].start < start && user_vma_owned[i].end > end
                && !user_vma_reserve(1)) return -1;
        }
    }
    int ret = user_vma_kernel_unmap(addr, size);
    if (!ret) {
        user_vma_forget((uintptr_t)addr, size);
        size_t page = user_vma_page();
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

/* GROWSDOWN/GROWSUP protection changes extend to the containing kernel VMA.
 * Read its bounds before mprotect can split it; ordinary calls skip this scan. */
static int user_vma_protect_span(uintptr_t* addr, size_t* size, int prot)
{
    int grow = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    /* Leave argument validation to mprotect before a maps lookup can mask
     * EINVAL with ENOMEM, or alter the span of an invalid request. */
    if (!*size || !grow || grow == (PROT_GROWSDOWN | PROT_GROWSUP)
        || (*addr & (user_vma_page() - 1))) return 0;
    int fd = open("/proc/thread-self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[4096], line[128];
    size_t used = 0;
    uintptr_t below = 0;
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            int error = errno;
            close(fd);
            errno = error;
            return -1;
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
            if (*addr < start || *addr >= end) { below = end; continue; }
            /* The main stack takes this protection as it grows, down to the
             * mapping below it: a fixed guest mapping may lie in its range. */
            if ((prot & PROT_GROWSDOWN) && end == user_vma_stack_high && start >= user_vma_stack_low)
                start = below > user_vma_stack_low ? below : user_vma_stack_low;
            if (prot & PROT_GROWSDOWN) { *size += *addr - start; *addr = start; }
            if (prot & PROT_GROWSUP) *size = end - *addr;
            close(fd);
            return 0;
        }
    }
    close(fd);
    errno = ENOMEM;
    return -1;
}

/* Callers hold the fd guard. Returns 1 when [start, end) is entirely mapped
 * with exactly the read/write/execute bits of prot, 0 when it is not, and
 * -1 when the kernel maps cannot be read. */
static int user_vma_kernel_prot(uintptr_t start, uintptr_t end, int prot)
{
    int fd = open("/proc/thread-self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    prot &= PROT_READ | PROT_WRITE | PROT_EXEC;
    char buffer[4096], line[128];
    size_t used = 0;
    uintptr_t covered = start;
    int result = 0;
    ssize_t count;
    while (!result && covered < end && (count = read(fd, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            result = -1;
            break;
        }
        for (ssize_t i = 0; i < count && !result && covered < end; ++i) {
            if (buffer[i] != '\n') {
                if (used < sizeof(line) - 1) line[used++] = buffer[i];
                continue;
            }
            line[used] = 0;
            used = 0;
            char* delimiter;
            uintptr_t first = strtoull(line, &delimiter, 16);
            if (*delimiter != '-') continue;
            uintptr_t last = strtoull(delimiter + 1, &delimiter, 16);
            if (last <= covered) continue;
            if (first > covered || delimiter[0] != ' ' || !delimiter[1] || !delimiter[2] || !delimiter[3]
                || ((delimiter[1] == 'r' ? PROT_READ : 0) | (delimiter[2] == 'w' ? PROT_WRITE : 0)
                    | (delimiter[3] == 'x' ? PROT_EXEC : 0)) != prot) {
                result = 2;
                break;
            }
            covered = last;
        }
    }
    close(fd);
    if (result < 0) return -1;
    return result == 0 && covered >= end;
}

/* Accounts for the mapped range [first, last) in an address-ordered scan.
 * Returns true once the scan has passed high. */
static bool user_vma_gap_take(uintptr_t first, uintptr_t last, size_t span, uintptr_t low,
                              uintptr_t high, uintptr_t* previous, uintptr_t* best)
{
    if (last <= low) return false;
    uintptr_t limit = first < high ? first : high;
    if (*previous <= limit && span <= limit - *previous) *best = limit - span;
    if (last >= high) { *previous = high; return true; }
    if (last > *previous) *previous = last;
    return false;
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
    /* The stack's growth range counts as mapped, in address order. */
    bool stack_pending = user_vma_stack_high > user_vma_stack_low;
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
            if (stack_pending && user_vma_stack_low <= start) {
                stack_pending = false;
                if (user_vma_gap_take(user_vma_stack_low, user_vma_stack_high, span, low, high,
                                      &previous, &best)) goto done;
            }
            if (user_vma_gap_take(start, end, span, low, high, &previous, &best)) goto done;
        }
    }
    if (stack_pending)
        user_vma_gap_take(user_vma_stack_low, user_vma_stack_high, span, low, high, &previous, &best);
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
    size_t page = user_vma_map_page(flags);
    if (!page || page >= user_vma_layout.limit) { errno = ENOMEM; return MAP_FAILED; }
    if (!size || size > user_vma_layout.limit - page) { errno = size ? ENOMEM : EINVAL; return MAP_FAILED; }
    size_t span = (size + page - 1) & ~(page - 1);
    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        if (!user_vma_range((uintptr_t)addr, span)) { errno = ENOMEM; return MAP_FAILED; }
        return user_vma_kernel_map(addr, size, prot, flags, fd, offset);
    }
    if (addr && user_vma_range((uintptr_t)addr, span)) {
        void* ret = user_vma_kernel_map(addr, size, prot, flags, fd, offset);
        if (ret == MAP_FAILED || user_vma_range((uintptr_t)ret, span)) return ret;
        user_vma_kernel_unmap(ret, span);
    }
#ifdef MAP_SHARED_VALIDATE
    if ((flags & 0x0f) == MAP_SHARED_VALIDATE) {
        /* Linux validates every flag of this type, and MAP_FIXED_NOREPLACE is
         * outside its legacy set: placing the mapping that way would fail
         * where the guest's call succeeds. Reserve the range, then replace
         * only that reservation, keeping the guest's own flags. */
        void* reserved = user_vma_map_raw(NULL, size, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | (flags & (MAP_HUGETLB | (63U << 26))), -1, 0);
        if (reserved == MAP_FAILED) return reserved;
        void* ret = user_vma_kernel_map(reserved, size, prot, flags | MAP_FIXED, fd, offset);
        if (ret == MAP_FAILED) {
            int error = errno;
            user_vma_kernel_unmap(reserved, span);
            errno = error;
        }
        return ret;
    }
#endif
    uintptr_t top = __atomic_load_n(&user_vma_cursor, __ATOMIC_RELAXED);
    if (!top) {
        uint32_t random = 0;
        /* Raw: glibc 2.41+ getrandom allocates vDSO state under a process lock. */
        if (syscall(SYS_getrandom, &random, sizeof(random), 0) != sizeof(random))
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
            next = (top >= floor + span ? top - span : user_vma_layout.top - span) & ~(page - 1);
            if (user_vma_stack_overlaps(next, span) && user_vma_stack_low >= floor + span)
                next = (user_vma_stack_low - span) & ~(page - 1);
        } while (!__atomic_compare_exchange_n(&user_vma_cursor, &top, next, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
        if (!user_vma_stack_overlaps(next, span)) {
            void* ret = user_vma_kernel_map((void*)next, size, prot, flags | MAP_FIXED_NOREPLACE, fd, offset);
            if (ret != MAP_FAILED || errno != EEXIST) return ret;
        }
    }
    for (unsigned retry = 0; retry < 128; ++retry) {
        uintptr_t next = user_vma_gap(span + page - user_vma_page(),
                                     UINT64_C(0x10000), user_vma_layout.top);
        if (!next) { errno = ENOMEM; return MAP_FAILED; }
        next = (next + page - 1) & ~(page - 1);
        void* ret = user_vma_kernel_map((void*)next, size, prot, flags | MAP_FIXED_NOREPLACE, fd, offset);
        if (ret != MAP_FAILED || errno != EEXIST) return ret;
    }
    errno = ENOMEM;
    return MAP_FAILED;
}

static void* user_vma_map(void* addr, size_t size, int prot, int flags, int fd, off_t offset)
{
    size_t page = user_vma_map_page(flags);
    /* Argument errors must not be replaced by a metadata allocation failure. */
    if (!size || !page || page >= user_vma_layout.limit || size > user_vma_layout.limit - page
        || offset % user_vma_page()
        || ((flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) && (uintptr_t)addr % page)
        || (!(flags & MAP_ANONYMOUS) && user_vma_kernel_valid(fd) < 0))
        return user_vma_map_raw(addr, size, prot, flags, fd, offset);
    if (!user_vma_reserve(1)) return MAP_FAILED;
    void* ret = user_vma_map_raw(addr, size, prot, flags, fd, offset);
    if (ret != MAP_FAILED) {
        size_t page = user_vma_map_page(flags);
        user_vma_remember((uintptr_t)ret, (size + page - 1) & ~(page - 1));
    }
    return ret;
}

static void* user_vma_remap_raw(void* addr, size_t oldsize, size_t newsize, int flags, void* newaddr)
{
    if (flags & MREMAP_DONTUNMAP) {
        size_t page = user_vma_page();
        uintptr_t old = (uintptr_t)addr, hint = (uintptr_t)newaddr;
        if (!(flags & MREMAP_MAYMOVE) || oldsize != newsize || hint % page
            || !user_vma_range(hint, newsize)
            || (old + oldsize > hint && hint + newsize > old)) {
            errno = EINVAL;
            return MAP_FAILED;
        }
    }
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
        return user_vma_kernel_remap(addr, oldsize, newsize, flags, newaddr);
    if (!(flags & MREMAP_DONTUNMAP) && oldsize && user_vma_range((uintptr_t)addr, newsize)) {
        void* ret = user_vma_kernel_remap(addr, oldsize, newsize, flags & ~MREMAP_MAYMOVE, NULL);
        if (ret != MAP_FAILED || errno != ENOMEM) return ret;
    }
    /* DONTUNMAP uses newaddr as a hint even without FIXED. Reserve it with
     * ordinary mmap placement, so an occupied hint is never overwritten. */
    void* hint = (flags & MREMAP_DONTUNMAP) ? newaddr : NULL;
    void* dest = user_vma_map_raw(hint, newsize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (dest == MAP_FAILED) return dest;
    void* ret = user_vma_kernel_remap(addr, oldsize, newsize, flags | MREMAP_FIXED, dest);
    if (ret == MAP_FAILED) {
        int error = errno;
        user_vma_kernel_unmap(dest, newsize);
        errno = error;
    }
    return ret;
}

static void* user_vma_remap(void* addr, size_t oldsize, size_t newsize, int flags, void* newaddr)
{
    size_t page = user_vma_page();
    if (!newsize || (uintptr_t)addr % page
        || (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP))
        || ((flags & (MREMAP_FIXED | MREMAP_DONTUNMAP)) && !(flags & MREMAP_MAYMOVE))
        || ((flags & MREMAP_FIXED) && (uintptr_t)newaddr % page))
        return user_vma_remap_raw(addr, oldsize, newsize, flags, newaddr);
    if (!user_vma_reserve(2)) return MAP_FAILED;
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
    if (user_vma_kernel_shmctl(id, IPC_STAT, &info)) return (void*)-1;
    if (!addr && (flags & SHM_REMAP)) { errno = EINVAL; return (void*)-1; }
    if (addr) {
        if (!user_vma_range((uintptr_t)addr, info.shm_segsz)) { errno = EINVAL; return (void*)-1; }
        if (!user_vma_reserve(1)) return (void*)-1;
        void* ret = user_vma_kernel_shmat(id, addr, flags);
        if (ret != (void*)-1) user_vma_remember((uintptr_t)ret, info.shm_segsz);
        return ret;
    }
    if (!user_vma_reserve(1)) return (void*)-1;
    void* dest = user_vma_map_raw(NULL, info.shm_segsz, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dest == MAP_FAILED) return dest;
    void* ret = user_vma_kernel_shmat(id, dest, flags | SHM_REMAP);
    if (ret == (void*)-1) {
        int error = errno;
        user_vma_kernel_unmap(dest, info.shm_segsz);
        errno = error;
    } else user_vma_remember((uintptr_t)ret, info.shm_segsz);
    return ret;
}

/* shmdt removes only this attachment's surviving SysV fragments. A guest may
 * have replaced an interior page with mmap; keep that replacement owned.
 * Compare kernel mapping identities, so a native allocation reusing a detached
 * hole cannot accidentally become guest memory on the next vfork. */
struct user_vma_fragment { uintptr_t start, end; unsigned long offset, inode; unsigned major, minor; };

static bool user_vma_shmdt_fragment(const char* line, struct user_vma_fragment* range)
{
    return sscanf(line, "%lx-%lx %*s %lx %x:%x %lu", &range->start, &range->end,
                  &range->offset, &range->major, &range->minor, &range->inode) == 6;
}

static int user_vma_shmdt(void* addr)
{
    struct user_vma_fragment *fragments = NULL;
    size_t count = 0;
    /* No stdio: a raw fork would copy its stream list lock held by a peer. */
    struct user_proc_reader maps;
    if (!user_proc_open(&maps, "/proc/thread-self/maps")) return -1;
    char line[4096];
    while (user_proc_line(&maps, line, sizeof(line))) {
        struct user_vma_fragment range;
        if (!user_vma_shmdt_fragment(line, &range)
            || !strstr(line, "/SYSV") || (!range.inode && !range.major && !range.minor)
            || range.start < (uintptr_t)addr || range.start - (uintptr_t)addr != range.offset) continue;
        void* grown = realloc(fragments, (count + 1) * sizeof(*fragments));
        if (!grown) { user_proc_close(&maps); free(fragments); return -1; }
        fragments = grown;
        fragments[count++] = range;
    }
    if (count > SIZE_MAX / 2 || !user_vma_reserve(count * 2)) {
        int error = count > SIZE_MAX / 2 ? ENOMEM : errno;
        user_proc_close(&maps);
        free(fragments);
        errno = error;
        return -1;
    }
    int ret = user_vma_kernel_shmdt(addr), saved = errno;
    if (!ret) {
        for (size_t i = 0; i < count; ++i) {
            struct user_vma_fragment old = fragments[i];
            uintptr_t cursor = old.start;
            /* Rewind the same view, as rewind(3) did: keep the descriptor. */
            syscall(SYS_lseek, maps.fd, 0, SEEK_SET);
            maps.cursor = maps.available = 0;
            while (user_proc_line(&maps, line, sizeof(line))) {
                struct user_vma_fragment current;
                if (!user_vma_shmdt_fragment(line, &current)
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
    user_proc_close(&maps);
    free(fragments);
    errno = saved;
    return ret;
}
#endif
