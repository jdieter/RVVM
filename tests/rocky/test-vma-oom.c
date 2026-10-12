/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#include "utils.h"
#include <assert.h>
#include <sys/resource.h>
#include "core/rvvm_user_vma.h"

int main(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    /* Fill ownership metadata with separate ranges, including a range which
     * needs a new record when its middle page is removed. */
    size_t count = 256, size = (count * 2 + 3) * page;
    char* space = user_vma_map_raw(NULL, size, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(space != MAP_FAILED && !munmap(space, size));
    assert(user_vma_map(space, page * 3, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == space);
    for (size_t i = 1; i < count; ++i) {
        char* address = space + (i * 2 + 2) * page;
        assert(user_vma_map(address, page, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == address);
    }
    assert(user_vma_owned_count == user_vma_owned_capacity);
    space[page] = 42;
    struct rlimit saved, limit = {1, RLIM_INFINITY};
    assert(!getrlimit(RLIMIT_AS, &saved));
    limit.rlim_max = saved.rlim_max;
    assert(!setrlimit(RLIMIT_AS, &limit));
    assert(user_vma_map(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
           == MAP_FAILED && errno == EINVAL);
    assert(user_vma_unmap(space + 1, page) == -1 && errno == EINVAL);
    assert(user_vma_remap(space + 1, page, page, 0, NULL) == MAP_FAILED && errno == EINVAL);
    errno = 0;
    assert(user_vma_unmap(space + page, page) == -1 && errno == ENOMEM);
    assert(space[page] == 42 && user_vma_owned_count == count);
    /* Freeing an entire range must still work without allocating metadata. */
    assert(!user_vma_unmap(space + page * 4, page));
    assert(!setrlimit(RLIMIT_AS, &saved));
    assert(!user_vma_unmap(space + page, page));
    assert(!user_vma_unmap(space, size));
    puts("PASS ownership metadata exhaustion preserves mappings and permits cleanup");
}
