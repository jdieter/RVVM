/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_EXEC_RANGES_H
#define RVVM_USER_EXEC_RANGES_H

#include "util/utils.h"
#include "util/vector.h"
#include <string.h>

/* Caller owns mmap_lock. Keep sorted, disjoint, nonadjacent executable ranges. */
struct user_exec_range { uintptr_t start, end; };
static vector_t(struct user_exec_range) user_exec_ranges;

static bool user_exec_ranges_contains(uintptr_t addr)
{
    size_t lo = 0, hi = vector_size(user_exec_ranges);
    if (hi <= 8) {
        vector_foreach(user_exec_ranges, i) {
            const struct user_exec_range* r = &vector_at(user_exec_ranges, i);
            if (addr >= r->start && addr < r->end) return true;
        }
        return false;
    }
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const struct user_exec_range* r = &vector_at(user_exec_ranges, mid);
        if (addr < r->start) hi = mid;
        else if (addr >= r->end) lo = mid + 1;
        else return true;
    }
    return false;
}

/* Return whether previously executable pages were touched, for invalidation. */
static bool user_exec_ranges_update(uintptr_t start, size_t size, bool executable)
{
    if (!size || start > UINTPTR_MAX - 4095 || size > UINTPTR_MAX - 4095 - start) return false;
    uintptr_t end = (start + size + 4095) & ~(uintptr_t)4095;
    start &= ~(uintptr_t)4095;
    const uintptr_t original_start = start, original_end = end;
    size_t count = vector_size(user_exec_ranges), lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uintptr_t edge = vector_at(user_exec_ranges, mid).end;
        if (edge < start || (!executable && edge == start)) lo = mid + 1;
        else hi = mid;
    }
    size_t first = lo, last = first;
    bool removed = false;
    while (last < count) {
        struct user_exec_range r = vector_at(user_exec_ranges, last);
        if (r.start > end || (!executable && r.start == end)) break;
        removed |= r.end > original_start && r.start < original_end;
        if (executable) {
            start = EVAL_MIN(start, r.start);
            end = EVAL_MAX(end, r.end);
        }
        ++last;
    }
    struct user_exec_range replacement[2];
    size_t added = 0;
    if (executable) replacement[added++] = (struct user_exec_range){start, end};
    else if (last > first) {
        struct user_exec_range left = vector_at(user_exec_ranges, first);
        struct user_exec_range right = vector_at(user_exec_ranges, last - 1);
        if (left.start < start) replacement[added++] = (struct user_exec_range){left.start, start};
        if (right.end > end) replacement[added++] = (struct user_exec_range){end, right.end};
    }
    size_t next_count = count - (last - first) + added;
    while (vector_size(user_exec_ranges) < next_count) {
        struct user_exec_range empty = {0};
        vector_push_back(user_exec_ranges, empty);
    }
    if (last != first + added && last < count)
        memmove(vector_buffer(user_exec_ranges) + first + added,
                vector_buffer(user_exec_ranges) + last,
                (count - last) * sizeof(struct user_exec_range));
    for (size_t i = 0; i < added; ++i) vector_at(user_exec_ranges, first + i) = replacement[i];
    user_exec_ranges.count = next_count;
    return removed;
}
#endif
