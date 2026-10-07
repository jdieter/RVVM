/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_MEMORY_H
#define RVVM_USER_MEMORY_H

/* Data protection stays with the host kernel. Execution needs its own map:
 * reading an instruction is not an executable access from the host's view. */
#include "rvvm_user_exec_ranges.h"

static bool user_exec_check(rvvm_addr_t addr)
{
    spin_lock(&mmap_lock);
    bool allowed = user_exec_ranges_contains(addr);
    spin_unlock(&mmap_lock);
    return allowed;
}

static void user_exec_update(uintptr_t start, size_t size, bool executable)
{
    if (user_exec_ranges_update(start, size, executable)) {
        uintptr_t first = start & ~(uintptr_t)4095;
        uintptr_t end = (start + size + 4095) & ~(uintptr_t)4095;
        rvvm_flush_icache(userland, first, end - first);
    }
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
        if (mprotect((void*)start, (addr + size + 4095 - start) & ~(size_t)4095, prot)) abort();
    }
}

static void user_exec_trampoline(void* addr)
{
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
}

static rvvm_addr_t user_mremap(uintptr_t addr, size_t oldsize, size_t newsize, int flags, uintptr_t newaddr)
{
    user_fd_lock();
    spin_lock(&mmap_lock);
    struct user_exec_move move = ZERO_INIT;
    user_exec_move_prepare(&move, addr, oldsize, newsize);
    rvvm_addr_t ret = errno_ret((uintptr_t)user_vma_remap((void*)addr, oldsize, newsize, flags, (void*)newaddr));
    if (ret < (rvvm_addr_t)-4095) user_exec_move_apply(&move, addr, oldsize, newsize, flags, ret);
    vector_free(move.ranges);
    spin_unlock(&mmap_lock);
    user_fd_unlock();
    return ret;
}
#endif
