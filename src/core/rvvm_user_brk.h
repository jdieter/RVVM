/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_BRK_H
#define RVVM_USER_BRK_H

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include "rvvm_user_vma.h"

#define UAPI_BRK_WINDOW (user_vma_layout.brk_window)

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
        /* Leave growth room below the ordinary mmap arena, without mapping
         * it: even PROT_NONE reservations count against host RLIMIT_AS. */
        uintptr_t base = user_vma_gap(UAPI_BRK_WINDOW, user_vma_layout.low,
                                     user_vma_layout.low + UAPI_BRK_WINDOW * 2);
        if (!base) return 0;
        heap->base = heap->current = heap->committed = base;
        heap->page_size = (size_t)page;
    }
    if (requested < heap->base || requested - heap->base > UAPI_BRK_WINDOW)
        return heap->current;

    uintptr_t end = (requested + heap->page_size - 1) & ~(heap->page_size - 1);
    if (end > heap->committed) {
        /* New mappings let the kernel enforce AS/DATA limits and arbitrate
         * collisions. Never replace an unrelated mapping to grow the heap. */
        void* mapped = user_vma_map((void*)heap->committed, end - heap->committed,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (mapped == MAP_FAILED) return heap->current;
    } else if (end < heap->committed) {
        size_t length = heap->committed - end;
        /* Release the kernel charge; keep bytes in the partial last page. */
        if (user_vma_unmap((void*)end, length)) return heap->current;
    }
    heap->committed = end;
    heap->current = requested;
    return requested;
}

#endif
