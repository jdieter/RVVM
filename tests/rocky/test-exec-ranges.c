/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "util/vector.h"
#include "core/rvvm_user_exec_ranges.h"

int main(void)
{
    for (size_t i = 40000; i; --i)
        assert(!user_exec_ranges_update(i * 4096, 4096, true));
    assert(vector_size(user_exec_ranges) == 1);
    assert(user_exec_ranges_update(8192, 4096, false));
    assert(vector_size(user_exec_ranges) == 2 && !user_exec_ranges_contains(8192));
    assert(user_exec_ranges_update(8192, 4096, true) == false);
    assert(vector_size(user_exec_ranges) == 1);
    assert(user_exec_ranges_update(0, 40001 * 4096, false));
    assert(!vector_size(user_exec_ranges));
    // Compare interval operations with a page bitmap, including splits/merges.
    bool pages[128] = {0};
    uint32_t random = 123;
    for (unsigned trial = 0; trial < 20000; ++trial) {
        random = random * 1664525 + 1013904223;
        unsigned first = random % 128;
        random = random * 1664525 + 1013904223;
        unsigned count = 1 + random % (128 - first);
        bool executable = random & 0x100;
        bool touched = false;
        for (unsigned i = first; i < first + count; ++i) { touched |= pages[i]; pages[i] = executable; }
        assert(user_exec_ranges_update(first * 4096, count * 4096, executable) == touched);
        for (unsigned i = 0; i < 128; ++i) assert(user_exec_ranges_contains(i * 4096) == pages[i]);
        for (size_t i = 1; i < vector_size(user_exec_ranges); ++i)
            assert(vector_at(user_exec_ranges, i - 1).end < vector_at(user_exec_ranges, i).start);
    }
    vector_free(user_exec_ranges);
    puts("PASS 40000 adjacent executable pages and randomized permission transitions");
}
