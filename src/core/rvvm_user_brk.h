/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_BRK_H
#define RVVM_USER_BRK_H

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include "rvvm_user_vma.h"

#define UAPI_BRK_RESERVE (user_vma_layout.brk_reserve)

struct uapi_brk_heap {
    uintptr_t base, current, committed;
    size_t page_size;
};

/* Caller serializes access. Never move the heap: guest pointers must stay valid. */
static inline uintptr_t uapi_brk(struct uapi_brk_heap *heap, uintptr_t requested)
{
    if (!heap->base) {
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0) return 0;
        void *base = user_vma_map(NULL, UAPI_BRK_RESERVE, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (base == MAP_FAILED) return 0;
        heap->base = heap->current = heap->committed = (uintptr_t)base;
        heap->page_size = (size_t)page;
    }
    if (requested < heap->base || requested - heap->base > UAPI_BRK_RESERVE)
        return heap->current;

    uintptr_t end = (requested + heap->page_size - 1) & ~(heap->page_size - 1);
    if (end > heap->committed) {
        // Anonymous pages are already zero-filled; do not populate them eagerly.
        if (mprotect((void*)heap->committed, end - heap->committed,
                     PROT_READ | PROT_WRITE)) return heap->current;
    } else if (end < heap->committed) {
        size_t length = heap->committed - end;
        if (mprotect((void*)end, length, PROT_NONE)) return heap->current;
        // Preserve the partial last page; discard only complete released pages.
        if (madvise((void*)end, length, MADV_DONTNEED)) {
            mprotect((void*)end, length, PROT_READ | PROT_WRITE);
            return heap->current;
        }
    }
    heap->committed = end;
    heap->current = requested;
    return requested;
}

#endif
