/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_MEMORY_H
#define RVVM_USER_MEMORY_H

/* Data protection stays with the host kernel. Execution needs its own map:
 * reading an instruction is not an executable access from the host's view. */
#include "rvvm_user_exec_ranges.h"
struct user_exec_snapshot {
    struct user_exec_snapshot* next;
    size_t count, capacity;
    struct user_exec_range ranges[];
};
static struct user_exec_snapshot* user_exec_snapshot;
static struct user_exec_snapshot* user_exec_retired;
static struct user_exec_snapshot* user_exec_reserved;
struct user_exec_reader {
    struct user_exec_reader* next;
    struct user_exec_snapshot* snapshot;
};
static struct user_exec_reader* user_exec_readers;
static size_t user_exec_native_readers;
static THREAD_LOCAL struct user_exec_reader* user_native_exec_reader;
static THREAD_LOCAL bool user_exec_deferred;

static bool user_exec_reserve(size_t additional)
{
    if (!user_exec_native_readers) return true;
    size_t count = vector_size(user_exec_ranges);
    if (additional > (SIZE_MAX - sizeof(struct user_exec_snapshot)) / sizeof(struct user_exec_range) - count)
        return false;
    size_t capacity = count + additional;
    if (user_exec_reserved && user_exec_reserved->capacity >= capacity) return true;
    struct user_exec_snapshot* next = malloc(sizeof(*next) + capacity * sizeof(*next->ranges));
    if (!next) return false;
    next->capacity = capacity;
    free(user_exec_reserved);
    user_exec_reserved = next;
    return true;
}

/* mmap_lock protects writers and lifetime enrollment. A killable reader
 * publishes one hazard pointer instead of owning a lock. SIGKILL may retain
 * that one snapshot until its parent removes the reader, never an unbounded
 * history of executable mapping changes. */
static void user_exec_collect(void)
{
    struct user_exec_snapshot** slot = &user_exec_retired;
    while (*slot) {
        struct user_exec_snapshot* candidate = *slot;
        bool referenced = false;
        for (struct user_exec_reader* r = user_exec_readers; r; r = r->next)
            referenced |= atomic_load_pointer_ex(&r->snapshot, ATOMIC_SEQ_CST) == candidate;
        if (referenced) slot = &candidate->next;
        else { *slot = candidate->next; free(candidate); }
    }
}

static bool user_exec_publish(void)
{
    size_t count = vector_size(user_exec_ranges);
    struct user_exec_snapshot* old = atomic_load_pointer(&user_exec_snapshot);
    if (old && old->count == count
        && !memcmp(old->ranges, vector_buffer(user_exec_ranges), count * sizeof(*old->ranges))) return true;
    struct user_exec_snapshot* next = user_exec_reserved;
    if (next && next->capacity >= count) user_exec_reserved = NULL;
    else {
        next = malloc(sizeof(*next) + count * sizeof(*next->ranges));
        if (next) next->capacity = count;
    }
    if (!next) return false;
    next->count = count;
    next->next = NULL;
    memcpy(next->ranges, vector_buffer(user_exec_ranges), count * sizeof(*next->ranges));
    atomic_store_pointer_ex(&user_exec_snapshot, next, ATOMIC_SEQ_CST);
    if (old) {
        old->next = user_exec_retired;
        user_exec_retired = old;
    }
    user_exec_collect();
    return true;
}

static bool user_exec_native_enter(struct user_exec_reader* reader)
{
    spin_lock(&mmap_lock);
    bool ready = user_exec_publish();
    if (ready) {
        ++user_exec_native_readers;
        reader->next = user_exec_readers;
        user_exec_readers = reader;
    }
    spin_unlock(&mmap_lock);
    return ready;
}

static void user_exec_native_leave(struct user_exec_reader* reader)
{
    spin_lock(&mmap_lock);
    struct user_exec_reader** slot = &user_exec_readers;
    while (*slot != reader) slot = &(*slot)->next;
    *slot = reader->next;
    atomic_store_pointer_ex(&reader->snapshot, NULL, ATOMIC_SEQ_CST);
    user_exec_collect();
    if (!--user_exec_native_readers) {
        struct user_exec_snapshot* current = atomic_load_pointer(&user_exec_snapshot);
        atomic_store_pointer(&user_exec_snapshot, NULL);
        current->next = user_exec_retired;
        while (current) {
            struct user_exec_snapshot* next = current->next;
            free(current);
            current = next;
        }
        user_exec_retired = NULL;
        free(user_exec_reserved);
        user_exec_reserved = NULL;
    }
    spin_unlock(&mmap_lock);
}

/* Call in a new private mm, with mmap_lock inherited from its coherent
 * snapshot and libc child recovery complete. Parent readers don't survive
 * fork; retaining their hazards would pin every later mapping snapshot. */
static void user_exec_fork_child(void)
{
    free(user_exec_snapshot);
    while (user_exec_retired) {
        struct user_exec_snapshot* next = user_exec_retired->next;
        free(user_exec_retired);
        user_exec_retired = next;
    }
    free(user_exec_reserved);
    user_exec_snapshot = user_exec_reserved = NULL;
    user_exec_readers = NULL;
    user_exec_native_readers = 0;
    user_native_exec_reader = NULL;
    user_exec_deferred = false;
}

static bool user_exec_check(rvvm_addr_t addr)
{
    if (user_native_exec_reader) {
        for (;;) {
            /* Observe a quiescent writer, without acquiring its lock. The
             * final pointer/lock check retries if permissions changed. */
            if (atomic_load_uint32(&mmap_lock.flag)) continue;
            const struct user_exec_snapshot* snapshot = atomic_load_pointer_ex(&user_exec_snapshot, ATOMIC_SEQ_CST);
            atomic_store_pointer_ex(&user_native_exec_reader->snapshot, (void*)snapshot, ATOMIC_SEQ_CST);
            if (snapshot != atomic_load_pointer_ex(&user_exec_snapshot, ATOMIC_SEQ_CST)
                || atomic_load_uint32(&mmap_lock.flag)) {
                atomic_store_pointer_ex(&user_native_exec_reader->snapshot, NULL, ATOMIC_SEQ_CST);
                continue;
            }
            size_t lo = 0, hi = snapshot->count;
            bool allowed = false;
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                struct user_exec_range range = snapshot->ranges[mid];
                if (addr < range.start) hi = mid;
                else if (addr >= range.end) lo = mid + 1;
                else { allowed = true; break; }
            }
            atomic_fence_ex(ATOMIC_ACQUIRE);
            bool consistent = !atomic_load_uint32(&mmap_lock.flag)
                && snapshot == atomic_load_pointer_ex(&user_exec_snapshot, ATOMIC_SEQ_CST);
            atomic_store_pointer_ex(&user_native_exec_reader->snapshot, NULL, ATOMIC_SEQ_CST);
            if (consistent) return allowed;
        }
    }
    spin_lock(&mmap_lock);
    bool allowed = user_exec_ranges_contains(addr);
    spin_unlock(&mmap_lock);
    return allowed;
}

static void user_exec_update(uintptr_t start, size_t size, bool executable)
{
    bool invalidated = user_exec_ranges_update(start, size, executable);
    if (user_exec_native_readers && !user_exec_deferred && !user_exec_publish()) {
        /* The kernel mutation already committed. Continuing with stale
         * execute permission would be incorrect, as would replaying it. */
        syscall(SYS_exit_group, 127);
    }
    if (invalidated) {
        uintptr_t first = start & ~(uintptr_t)4095;
        uintptr_t end = (start + size + 4095) & ~(uintptr_t)4095;
        rvvm_flush_icache(userland, first, end - first);
    }
}

/* A failed mprotect may still have changed a prefix of the range: Linux
 * applies VMAs in address order and stops at the first hole or failing VMA.
 * Each changed VMA now has exactly the requested host protection; the one
 * that failed does not. host_prot is the protection last requested, without
 * EXEC where the host refused it. The failing VMA still differs: Linux
 * refuses a VMA mprotect leaves unchanged only over EXEC, barring an LSM
 * policy change since it was mapped. Without readable maps, fail
 * closed: drop execute permission across a request that removed it, and
 * never add it. */
static void user_exec_partial(uintptr_t start, size_t size, int host_prot, bool executable)
{
    size_t page = user_vma_page();
    if (!size || start % page || size > SIZE_MAX - page + 1) return;
    uintptr_t end = start + ((size + page - 1) & ~(page - 1));
    if (end < start) return;
    int fd = open("/proc/thread-self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (!executable) user_exec_update(start, end - start, false);
        return;
    }
    char buffer[4096], line[128];
    size_t used = 0;
    uintptr_t changed = start;
    bool done = false;
    ssize_t count = 0;
    while (!done && (count = read(fd, buffer, sizeof(buffer))) != 0) {
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (ssize_t i = 0; i < count && !done; ++i) {
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
            if (last <= changed) continue;
            int prot = 0;
            if (delimiter[0] == ' ' && delimiter[1] && delimiter[2] && delimiter[3])
                prot = (delimiter[1] == 'r' ? PROT_READ : 0) | (delimiter[2] == 'w' ? PROT_WRITE : 0)
                     | (delimiter[3] == 'x' ? PROT_EXEC : 0);
            if (first > changed
                || prot != (host_prot & (PROT_READ | PROT_WRITE | PROT_EXEC))) done = true;
            else changed = last < end ? last : end;
            if (changed == end) done = true;
        }
    }
    close(fd);
    if (count < 0) {
        if (!executable) user_exec_update(start, end - start, false);
        return;
    }
    if (changed > start) user_exec_update(start, changed - start, executable);
}

/* Callers hold the fd guard and mmap_lock, with registry space reserved.
 * addr/size go to the kernel; [start, start + span) is the range they cover,
 * wider for GROWSDOWN/GROWSUP. Returns 0 or -errno. Kernel maps are compared
 * with the protection actually requested last, which lacks EXEC where the
 * host refused it (see user_vma_kernel_protect). */
static long user_exec_mprotect(uintptr_t addr, size_t size, uintptr_t start, size_t span,
                               int host_prot, bool executable)
{
    if (!user_vma_kernel_protect((void*)addr, size, &host_prot)) {
        user_exec_update(start, span, executable);
        return 0;
    }
    long ret = -errno;
    if (ret != -EINVAL) user_exec_partial(start, span, host_prot, executable);
    return ret;
}

/* Guest-executable ELF segments, stack and signal trampoline ask for host
 * EXEC too, so kernel maps show guest execute intent as for mmap, and do
 * without it where refused. */
static int user_exec_protect(void* addr, size_t size, int prot, bool executable)
{
    if (executable) prot |= PROT_READ | PROT_EXEC;
    return user_vma_kernel_protect(addr, size, &prot);
}

static void user_exec_elf(const elf_desc_t* elf)
{
    if (!elf->base || !elf->phdr_data) return;
    const unsigned char* ph = elf->phdr_data;
    bool class64 = elf->phentsize == 56;
    for (size_t i = 0; i < elf->phnum; ++i, ph += elf->phentsize) {
        if (read_uint32_le_m(ph) != 1) continue;
        unsigned flags = read_uint32_le_m(ph + (class64 ? 4 : 24));
        uintptr_t addr = elf->load_bias + (class64 ? read_uint64_le_m(ph + 16) : read_uint32_le_m(ph + 8));
        size_t size = class64 ? read_uint64_le_m(ph + 40) : read_uint32_le_m(ph + 20);
        if (!size) continue;
        user_exec_update(addr, size, flags & 1);
        uintptr_t start = addr & ~(uintptr_t)4095;
        int prot = (flags & 4 ? PROT_READ : 0) | (flags & 2 ? PROT_WRITE : 0) | (flags & 1 ? PROT_READ : 0);
        if (user_exec_protect((void*)start, (addr + size + 4095 - start) & ~(size_t)4095, prot, flags & 1))
            abort();
    }
}

static void user_exec_trampoline(void* addr)
{
    user_exec_protect(addr, 4096, PROT_READ, true);
    spin_lock(&mmap_lock);
    user_exec_update((uintptr_t)addr, 4096, true);
    spin_unlock(&mmap_lock);
}

static bool user_exec_stack(const elf_desc_t* elf)
{
    const unsigned char* ph = elf->phdr_data;
    for (size_t i = 0; ph && i < elf->phnum; ++i, ph += elf->phentsize)
        if (read_uint32_le_m(ph) == 0x6474e551) // PT_GNU_STACK
            return read_uint32_le_m(ph + (elf->phentsize == 56 ? 4 : 24)) & 1;
    return false;
}

struct user_exec_move {
    vector_t(struct user_exec_range) ranges;
    bool executable_tail;
};

static void user_exec_move_prepare(struct user_exec_move* move, uintptr_t addr, size_t oldsize, size_t newsize)
{
    size_t span = oldsize ? oldsize : newsize;
    vector_foreach(user_exec_ranges, i) {
        struct user_exec_range r = vector_at(user_exec_ranges, i);
        if (span && span <= UINTPTR_MAX - addr) {
            uintptr_t end = addr + span;
            if (end > r.start && end <= r.end) move->executable_tail = true;
            if (r.end > addr && r.start < end) {
                r.start = EVAL_MAX(r.start, addr) - addr;
                r.end = EVAL_MIN(r.end, end) - addr;
                vector_push_back(move->ranges, r);
            }
        }
    }
}

static void user_exec_move_apply(struct user_exec_move* move, uintptr_t addr, size_t oldsize,
                                  size_t newsize, int flags, uintptr_t ret)
{
    bool deferred = user_exec_deferred;
    user_exec_deferred = true;
    size_t span = oldsize ? oldsize : newsize;
        if (!(flags & MREMAP_DONTUNMAP)) user_exec_update(addr, oldsize, false);
        else rvvm_flush_icache(userland, addr, oldsize);
        user_exec_update(ret, newsize, false);
        vector_foreach(move->ranges, i) {
            struct user_exec_range r = vector_at(move->ranges, i);
            if (r.start < newsize)
                user_exec_update(ret + r.start, EVAL_MIN(r.end, newsize) - r.start, true);
        }
        if (newsize > span && move->executable_tail) user_exec_update(ret + span, newsize - span, true);
    user_exec_deferred = deferred;
    if (!deferred && user_exec_native_readers && !user_exec_publish()) syscall(SYS_exit_group, 127);
}

static rvvm_addr_t user_mremap(uintptr_t addr, size_t oldsize, size_t newsize, int flags, uintptr_t newaddr)
{
    user_fd_lock();
    spin_lock(&mmap_lock);
    if (!user_exec_reserve(vector_size(user_exec_ranges) + 4)) {
        spin_unlock(&mmap_lock);
        user_fd_unlock();
        return -ENOMEM;
    }
    user_exec_deferred = true;
    struct user_exec_move move = ZERO_INIT;
    user_exec_move_prepare(&move, addr, oldsize, newsize);
    rvvm_addr_t ret = errno_ret((uintptr_t)user_vma_remap((void*)addr, oldsize, newsize, flags, (void*)newaddr));
    if (ret < (rvvm_addr_t)-4095) user_exec_move_apply(&move, addr, oldsize, newsize, flags, ret);
    user_exec_deferred = false;
    if (user_exec_native_readers && !user_exec_publish()) syscall(SYS_exit_group, 127);
    vector_free(move.ranges);
    spin_unlock(&mmap_lock);
    user_fd_unlock();
    return ret;
}
#endif
